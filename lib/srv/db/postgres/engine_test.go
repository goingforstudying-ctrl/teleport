// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
)

// noopAuth implements common.Auth for testing. GetTLSConfig returns nil so
// that the engine connects over plain TCP, as required for testcontainers.
// Only the methods called during ActivateUser/DeactivateUser/DeleteUser are
// implemented; any other call will panic. This is a benefit, since a future
// panic signals a new code path that needs a real implementation.
type noopAuth struct {
	common.Auth
}

func (a *noopAuth) GetTLSConfig(_ context.Context, _ time.Time, _ types.Database, _ string) (*tls.Config, error) {
	return nil, nil
}
func (a *noopAuth) WithLogger(_ func(*slog.Logger) *slog.Logger) common.Auth { return a }
func (a *noopAuth) WithSession(_ *common.Session) common.Auth                { return a }

// noopChecker implements services.AccessChecker for testing. It returns empty
// database permissions, which causes applyPermissions to exit early.
type noopChecker struct {
	services.AccessChecker
}

func (c *noopChecker) GetDatabasePermissions(_ types.Database) (types.DatabasePermissions, types.DatabasePermissions, error) {
	return nil, nil, nil
}

// noopAudit implements common.Audit for testing. Only the methods called
// during ActivateUser/DeactivateUser/DeleteUser are implemented; any other
// call will panic.
type noopAudit struct {
	common.Audit
}

func (a *noopAudit) OnDatabaseUserCreate(_ context.Context, _ *common.Session, _ error) {}
func (a *noopAudit) OnDatabaseUserDeactivate(_ context.Context, _ *common.Session, _ bool, _ error) {
}

// makeSession returns a Session for the given database, username, and roles.
// A nil roles slice is normalised to an empty slice to avoid passing SQL NULL
// to the activate procedure's varchar[] parameter.
func makeSession(db types.Database, username string, roles []string) *common.Session {
	if roles == nil {
		roles = []string{}
	}
	return &common.Session{
		Database:      db,
		DatabaseUser:  username,
		DatabaseName:  "postgres",
		DatabaseRoles: roles,
		Checker:       &noopChecker{},
	}
}

// isMember reports whether username is a member of role in the database
// reached via conn.
func isMember(t *testing.T, conn *pgx.Conn, username, role string) bool {
	t.Helper()
	var exists bool
	err := conn.QueryRow(t.Context(),
		`SELECT true FROM pg_auth_members m
		 JOIN pg_roles member_role ON m.member = member_role.oid
		 JOIN pg_roles grant_role  ON m.roleid = grant_role.oid
		 WHERE member_role.rolname = $1 AND grant_role.rolname = $2`,
		username, role).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	require.NoError(t, err)
	return exists
}

// canLogin reports whether the named role has the LOGIN attribute.
func canLogin(t *testing.T, conn *pgx.Conn, username string) bool {
	t.Helper()
	var login bool
	err := conn.QueryRow(t.Context(),
		"SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", username).Scan(&login)
	require.NoError(t, err)
	return login
}

// userExists reports whether a role with the given name exists in pg_roles.
func userExists(t *testing.T, conn *pgx.Conn, username string) bool {
	t.Helper()
	var count int
	err := conn.QueryRow(t.Context(),
		"SELECT COUNT(*) FROM pg_roles WHERE rolname = $1", username).Scan(&count)
	require.NoError(t, err)
	return count > 0
}

// makeReassignSession returns a Session like makeSession but with
// AutoCreateUserMode set to BEST_EFFORT_REASSIGN_AND_DROP so DeleteUser
// runs the per-object reassignment path.
func makeReassignSession(db types.Database, username string, roles []string) *common.Session {
	s := makeSession(db, username, roles)
	s.AutoCreateUserMode = types.CreateDatabaseUserMode_DB_USER_MODE_BEST_EFFORT_REASSIGN_AND_DROP
	return s
}

// tableOwner returns the role that owns schema.name.
func tableOwner(t *testing.T, conn *pgx.Conn, schema, name string) string {
	t.Helper()
	var owner string
	err := conn.QueryRow(t.Context(), `
		SELECT pg_get_userbyid(c.relowner)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2`,
		schema, name).Scan(&owner)
	require.NoError(t, err)
	return owner
}

// schemaOwner returns the role that owns the named schema.
func schemaOwner(t *testing.T, conn *pgx.Conn, name string) string {
	t.Helper()
	var owner string
	err := conn.QueryRow(t.Context(),
		`SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = $1`,
		name).Scan(&owner)
	require.NoError(t, err)
	return owner
}

func TestUserAutoProvisioning(t *testing.T) {
	if run, _ := apiutils.ParseBool(os.Getenv("ENABLE_TESTCONTAINERS")); !run {
		// Docker Hub rate limits cause failures in CI, this test is disabled until we can set up an alternative to Docker Hub
		t.Skip("Test disabled in CI. Enable it by setting env variable ENABLE_TESTCONTAINERS")
	}
	pgContainer, err := postgres.Run(t.Context(), "postgres:18",
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.WithDatabase("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pgContainer.Terminate(context.Background()))
	})

	port, err := pgContainer.MappedPort(t.Context(), "5432/tcp")
	require.NoError(t, err)
	// The engine connects as the docs-prescribed least-privilege admin
	// user "teleport-admin", with CREATEROLE only — not SUPERUSER. The
	// URI includes credentials because the connector prepends
	// "postgres://" before parsing.
	dbURI := fmt.Sprintf("teleport-admin:admin@localhost:%s", port.Port())

	db, err := types.NewDatabaseV3(types.Metadata{
		Name: "test-pg",
	}, types.DatabaseSpecV3{
		Protocol: defaults.ProtocolPostgres,
		URI:      dbURI,
		AdminUser: &types.DatabaseAdminUser{
			Name: "teleport-admin",
		},
	})
	require.NoError(t, err)

	engine := &Engine{
		EngineConfig: common.EngineConfig{
			Log:   slog.Default(),
			Auth:  &noopAuth{},
			Audit: &noopAudit{},
		},
	}

	// bootstrapConn is the postgres superuser, kept alive for the test's
	// duration. It is used only for:
	//   (1) one-time setup of the teleport-admin user and the roles and
	//       grants Teleport's docs prescribe; and
	//   (2) per-test fixture operations that teleport-admin cannot do
	//       itself. In PG16+, the implicit grant from CREATEROLE-creating-
	//       a-role gives the creator ADMIN OPTION only — not SET ROLE.
	//       That means teleport-admin cannot ALTER … OWNER TO an
	//       auto-provisioned user even though it created the user.
	// Nothing under test runs through bootstrapConn; the engine, every
	// assertion query, and adminConn-driven DDL all use teleport-admin.
	connStr, err := pgContainer.ConnectionString(t.Context())
	require.NoError(t, err)
	bootstrapConn, err := pgx.Connect(t.Context(), connStr)
	require.NoError(t, err)
	t.Cleanup(func() { bootstrapConn.Close(context.Background()) })

	_, err = bootstrapConn.Exec(t.Context(), `
		-- Docs-prescribed admin: CREATEROLE + LOGIN. CREATEDB lets the
		-- test create the second database.
		CREATE USER "teleport-admin" LOGIN PASSWORD 'admin' CREATEROLE CREATEDB;

		-- Database-level grants the docs list as the "optional
		-- least-privilege" block. CREATE-on-db is needed for CREATE
		-- SCHEMA; CREATE-on-public so teleport-admin can issue DDL there.
		GRANT CREATE, CONNECT ON DATABASE postgres TO "teleport-admin";
		GRANT USAGE,  CREATE  ON SCHEMA   public   TO "teleport-admin";

		-- Pre-create teleport-object-inheritor so we can attach the
		-- schema-level and database-level CREATE grants that ALTER …
		-- OWNER TO inheritor requires the new owner to have. The role
		-- itself is also created lazily by ensureTeleportRole, but those
		-- grants belong on the role as such — schemas are not a
		-- Teleport-managed concern — and we want them in place before
		-- the first reassignment runs. (teleport-auto-user has no such
		-- grant requirement in these tests; ensureTeleportRole creates
		-- it on the first ActivateUser.)
		CREATE ROLE "teleport-object-inheritor";
		GRANT "teleport-object-inheritor" TO "teleport-admin";
		GRANT CREATE ON DATABASE postgres TO "teleport-object-inheritor";
		GRANT CREATE ON SCHEMA   public   TO "teleport-object-inheritor";

		-- postgres_fdw is bundled; install as superuser and grant USAGE so
		-- the foreign-table refused-case test can CREATE SERVER as
		-- teleport-admin.
		CREATE EXTENSION postgres_fdw;
		GRANT USAGE ON FOREIGN DATA WRAPPER postgres_fdw TO "teleport-admin";
	`)
	require.NoError(t, err)

	// CREATE DATABASE cannot be batched with other statements (it cannot
	// run inside a transaction block), so it has its own Exec call.
	_, err = bootstrapConn.Exec(t.Context(), `CREATE DATABASE other_db`)
	require.NoError(t, err)

	// Database and schema grants do not propagate across databases, so
	// re-grant teleport-admin inside other_db using a superuser connection
	// there. teleport-object-inheritor needs no other-db grants because
	// the dbid filter in reassign-objects.sql confines reassignment to the
	// current database.
	bootstrapOtherDBConn, err := pgx.Connect(t.Context(),
		fmt.Sprintf("postgres://postgres:postgres@localhost:%s/other_db", port.Port()))
	require.NoError(t, err)
	t.Cleanup(func() { bootstrapOtherDBConn.Close(context.Background()) })
	_, err = bootstrapOtherDBConn.Exec(t.Context(), `
		GRANT CREATE, CONNECT ON DATABASE other_db TO "teleport-admin";
		GRANT USAGE,  CREATE  ON SCHEMA   public   TO "teleport-admin";
	`)
	require.NoError(t, err)

	// adminConn drives every operation under test from teleport-admin's
	// vantage point: assertions, queries, and (via the dbURI above) the
	// engine itself.
	adminConn, err := pgx.Connect(t.Context(),
		fmt.Sprintf("postgres://teleport-admin:admin@localhost:%s/postgres", port.Port()))
	require.NoError(t, err)
	t.Cleanup(func() { adminConn.Close(context.Background()) })

	// otherDBConn is the teleport-admin peer for other_db, used by the
	// cross-db reassignment tests' assertions and fixtures that
	// teleport-admin can do itself.
	otherDBConn, err := pgx.Connect(t.Context(),
		fmt.Sprintf("postgres://teleport-admin:admin@localhost:%s/other_db", port.Port()))
	require.NoError(t, err)
	t.Cleanup(func() { otherDBConn.Close(context.Background()) })

	t.Run("ActivateUser", func(t *testing.T) {

		t.Run("creates new user", func(t *testing.T) {
			err := engine.ActivateUser(t.Context(), makeSession(db, "alice_new", nil))
			require.NoError(t, err)

			var exists bool
			err = adminConn.QueryRow(t.Context(),
				"SELECT true FROM pg_catalog.pg_user WHERE usename = $1", "alice_new").Scan(&exists)
			require.NoError(t, err)
			require.True(t, exists)
		})

		t.Run("reactivates deactivated user", func(t *testing.T) {
			// Use the engine for initial creation so that teleport-auto-user is set up.
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_reactivate", nil)))
			// Deactivate properly: revokes roles and sets NOLOGIN.
			require.NoError(t, engine.DeactivateUser(t.Context(), makeSession(db, "alice_reactivate", nil)))
			require.False(t, canLogin(t, adminConn, "alice_reactivate"), "precondition: login should be disabled")

			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_reactivate", nil)))
			require.True(t, canLogin(t, adminConn, "alice_reactivate"), "user should be able to log in after reactivation")
		})

		t.Run("assigns roles", func(t *testing.T) {
			_, err := adminConn.Exec(t.Context(), `CREATE ROLE testrole`)
			require.NoError(t, err)

			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_roles", []string{"testrole"})))
			require.True(t, isMember(t, adminConn, "alice_roles", "testrole"), "user should be member of testrole")
		})

		t.Run("preserves teleport-auto-user on reactivation", func(t *testing.T) {
			// First activation creates the user as a member of teleport-auto-user.
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_preserve", nil)))
			require.True(t, isMember(t, adminConn, "alice_preserve", "teleport-auto-user"),
				"precondition: user should be member of teleport-auto-user")

			// Deactivate properly: the deactivate procedure revokes roles but must
			// preserve teleport-auto-user membership.
			require.NoError(t, engine.DeactivateUser(t.Context(), makeSession(db, "alice_preserve", nil)))
			require.True(t, isMember(t, adminConn, "alice_preserve", "teleport-auto-user"),
				"teleport-auto-user membership must survive deactivate")

			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_preserve", nil)))
			require.True(t, isMember(t, adminConn, "alice_preserve", "teleport-auto-user"),
				"teleport-auto-user membership must survive deactivate/reactivate cycle")
		})

		t.Run("rejects pre-existing non-teleport user", func(t *testing.T) {
			// Create a user that Teleport did not provision (not in teleport-auto-user).
			_, err := adminConn.Exec(t.Context(), `CREATE USER "alice_external"`)
			require.NoError(t, err)

			err = engine.ActivateUser(t.Context(), makeSession(db, "alice_external", nil))
			require.True(t, trace.IsAlreadyExists(err), "expected AlreadyExists error, got: %v", err)
		})

		t.Run("active connection same roles succeeds", func(t *testing.T) {
			// Activate the user, then assign a password so we can open a connection as them.
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_active_same", nil)))
			_, err := adminConn.Exec(t.Context(),
				`ALTER USER "alice_active_same" WITH PASSWORD 'testpass' LOGIN`)
			require.NoError(t, err)

			userConn, err := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_active_same:testpass@localhost:%s/postgres", port.Port()))
			require.NoError(t, err)
			defer userConn.Close(context.Background())

			// ActivateUser with the same (empty) role set while a connection is open
			// should succeed because nothing changed.
			err = engine.ActivateUser(t.Context(), makeSession(db, "alice_active_same", nil))
			require.NoError(t, err)
		})

		t.Run("active connection different roles fails", func(t *testing.T) {
			_, err := adminConn.Exec(t.Context(), `CREATE ROLE role_for_diff`)
			require.NoError(t, err)

			// Activate the user without any roles, then assign a password.
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_active_diff", nil)))
			_, err = adminConn.Exec(t.Context(),
				`ALTER USER "alice_active_diff" WITH PASSWORD 'testpass' LOGIN`)
			require.NoError(t, err)

			userConn, err := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_active_diff:testpass@localhost:%s/postgres", port.Port()))
			require.NoError(t, err)
			defer userConn.Close(context.Background())

			// ActivateUser with a new role while a connection is open should fail
			// because the active session's roles would need to change.
			err = engine.ActivateUser(t.Context(), makeSession(db, "alice_active_diff", []string{"role_for_diff"}))
			require.True(t, trace.IsCompareFailed(err), "expected CompareFailed error, got: %v", err)
		})

		t.Run("self-heals teleport-auto-user role", func(t *testing.T) {
			// Drop teleport-auto-user to simulate it being removed out-of-band.
			// All members must be revoked before the role can be dropped.
			_, err := adminConn.Exec(t.Context(), `
			DO $$
			DECLARE r text;
			BEGIN
				FOR r IN
					SELECT member_role.rolname
					FROM pg_auth_members m
					JOIN pg_roles member_role ON m.member = member_role.oid
					WHERE m.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'teleport-auto-user')
				LOOP
					EXECUTE FORMAT('REVOKE "teleport-auto-user" FROM %I CASCADE', r);
				END LOOP;
			END $$;
			DROP ROLE "teleport-auto-user"`)
			require.NoError(t, err)

			// ActivateUser must recreate teleport-auto-user and assign the new user.
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_selfheal", nil)))
			require.True(t, isMember(t, adminConn, "alice_selfheal", "teleport-auto-user"),
				"ActivateUser should recreate teleport-auto-user and add the user to it")
		})

	})

	t.Run("DeactivateUser", func(t *testing.T) {

		t.Run("strips roles and disables login", func(t *testing.T) {
			_, err := adminConn.Exec(t.Context(), `CREATE ROLE testrole_deact`)
			require.NoError(t, err)

			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_deact_roles", []string{"testrole_deact"})))
			require.True(t, isMember(t, adminConn, "alice_deact_roles", "testrole_deact"), "precondition")
			require.True(t, canLogin(t, adminConn, "alice_deact_roles"), "precondition")

			require.NoError(t, engine.DeactivateUser(t.Context(), makeSession(db, "alice_deact_roles", nil)))

			require.False(t, isMember(t, adminConn, "alice_deact_roles", "testrole_deact"),
				"non-teleport role should be revoked after deactivation")
			require.False(t, canLogin(t, adminConn, "alice_deact_roles"),
				"login should be disabled after deactivation")
		})

		t.Run("is no-op when user has active connections", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_deact_active", nil)))
			_, err := adminConn.Exec(t.Context(),
				`ALTER USER "alice_deact_active" WITH PASSWORD 'testpass'`)
			require.NoError(t, err)

			userConn, err := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_deact_active:testpass@localhost:%s/postgres", port.Port()))
			require.NoError(t, err)
			defer userConn.Close(context.Background())

			require.NoError(t, engine.DeactivateUser(t.Context(), makeSession(db, "alice_deact_active", nil)))
			require.True(t, canLogin(t, adminConn, "alice_deact_active"),
				"login should remain enabled while an active connection is open")
		})

		t.Run("preserves teleport-auto-user membership", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_deact_preserve", nil)))
			require.NoError(t, engine.DeactivateUser(t.Context(), makeSession(db, "alice_deact_preserve", nil)))
			require.True(t, isMember(t, adminConn, "alice_deact_preserve", "teleport-auto-user"),
				"teleport-auto-user membership must be preserved after deactivation")
		})

	})

	t.Run("DeleteUser", func(t *testing.T) {

		t.Run("drops user with no owned objects", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_delete_clean", nil)))
			require.NoError(t, engine.DeleteUser(t.Context(), makeSession(db, "alice_delete_clean", nil)))
			require.False(t, userExists(t, adminConn, "alice_delete_clean"), "user should be dropped")
		})

		t.Run("does not drop user with active connections", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_delete_active", nil)))
			_, err := adminConn.Exec(t.Context(),
				`ALTER USER "alice_delete_active" WITH PASSWORD 'testpass' LOGIN`)
			require.NoError(t, err)

			userConn, err := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_delete_active:testpass@localhost:%s/postgres", port.Port()))
			require.NoError(t, err)
			defer userConn.Close(context.Background())

			require.NoError(t, engine.DeleteUser(t.Context(), makeSession(db, "alice_delete_active", nil)))
			require.True(t, userExists(t, adminConn, "alice_delete_active"), "user should still exist")
			require.True(t, canLogin(t, adminConn, "alice_delete_active"), "user should still have login")
		})

		t.Run("deactivates instead of dropping user who owns objects", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), makeSession(db, "alice_delete_owns", nil)))
			_, err := bootstrapConn.Exec(t.Context(), `
			CREATE TABLE alice_delete_owns_tbl (id int);
			ALTER TABLE alice_delete_owns_tbl OWNER TO "alice_delete_owns"`)
			require.NoError(t, err)

			// db has no OrphanedResourceOwner, so reassignment is skipped; the user
			// cannot be dropped and is deactivated instead.
			require.NoError(t, engine.DeleteUser(t.Context(), makeSession(db, "alice_delete_owns", nil)))
			require.True(t, userExists(t, adminConn, "alice_delete_owns"),
				"user should still exist (deactivated, not dropped)")
			require.False(t, canLogin(t, adminConn, "alice_delete_owns"),
				"user should have login disabled")
		})

	})

	t.Run("DeleteUser with reassignment", func(t *testing.T) {

		reassignSession := func(name string) *common.Session {
			return makeReassignSession(db, name, nil)
		}

		// sourceStillOwnsAnything reports whether username has any owner-deptype
		// rows in pg_shdepend for the current database. After a refused
		// reassignment, the savepoint rollback in delete-user.sql should leave
		// at least one such row.
		sourceStillOwnsAnything := func(t *testing.T, username string) bool {
			t.Helper()
			var n int
			// pg_roles is the public view over pg_authid; pg_authid itself
			// is restricted to superusers, so teleport-admin can't read it.
			err := adminConn.QueryRow(t.Context(), `
			SELECT COUNT(*) FROM pg_shdepend sd
			JOIN pg_roles r ON r.oid = sd.refobjid
			WHERE r.rolname = $1
			AND sd.deptype = 'o'
			AND sd.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())`,
				username).Scan(&n)
			require.NoError(t, err)
			return n > 0
		}

		// runReassignSuccess activates user, runs setup SQL that assigns
		// ownership to the user, calls DeleteUser, and asserts the user is
		// dropped. DROP USER fails with SQLSTATE 2BP01 if any object is still
		// owned by the user, so "user dropped" is sufficient proof that
		// reassignment landed on teleport-object-inheritor.
		//
		// setupSQL runs through bootstrapConn (superuser) because the
		// docs-prescribed teleport-admin lacks SET ROLE access to the
		// auto-provisioned user (PG16+ implicit grant is ADMIN-only), and
		// therefore cannot do ALTER … OWNER TO "alice". The production code
		// path under test still runs as teleport-admin.
		runReassignSuccess := func(t *testing.T, username, setupSQL string) {
			t.Helper()
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession(username)))
			_, err := bootstrapConn.Exec(t.Context(), setupSQL)
			require.NoError(t, err)
			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession(username)))
			require.False(t, userExists(t, adminConn, username), "user should be dropped after reassignment")
		}

		// runReassignRefused activates user, sets up an object that the
		// procedure will not reassign, calls DeleteUser, and asserts the user
		// is deactivated (still exists, no login) and still owns at least one
		// object (proving the BEGIN/EXCEPTION savepoint rolled back). See
		// runReassignSuccess for why setup runs through bootstrapConn.
		runReassignRefused := func(t *testing.T, username, setupSQL string) {
			t.Helper()
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession(username)))
			_, err := bootstrapConn.Exec(t.Context(), setupSQL)
			require.NoError(t, err)
			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession(username)))
			require.True(t, userExists(t, adminConn, username), "user should still exist (deactivated, not dropped)")
			require.False(t, canLogin(t, adminConn, username), "user should have login disabled")
			require.True(t, sourceStillOwnsAnything(t, username), "source should still own the offending object (savepoint rollback)")
		}

		// ─ Successful reassignment ──────────────────────────────────────────────

		t.Run("Reassign: bare table", func(t *testing.T) {
			// Canonical happy-path. Explicitly checks the inheritor is the
			// destination owner so this file pins down the target role.
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_re_bare")))
			_, err := bootstrapConn.Exec(t.Context(), `
			CREATE TABLE alice_re_bare_tbl (id int);
			ALTER TABLE alice_re_bare_tbl OWNER TO "alice_re_bare"`)
			require.NoError(t, err)
			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_re_bare")))
			require.False(t, userExists(t, adminConn, "alice_re_bare"))
			require.Equal(t, "teleport-object-inheritor", tableOwner(t, adminConn, "public", "alice_re_bare_tbl"))
		})

		t.Run("Reassign: table with index", func(t *testing.T) {
			runReassignSuccess(t, "alice_re_idx", `
			CREATE TABLE alice_re_idx_tbl (id int);
			CREATE INDEX alice_re_idx_tbl_idx ON alice_re_idx_tbl (id);
			ALTER TABLE alice_re_idx_tbl OWNER TO "alice_re_idx"`)
		})

		t.Run("Reassign: table with identity sequence", func(t *testing.T) {
			// Identity columns create OWNED BY sequences. ALTER TABLE OWNER TO
			// does not propagate to such sequences, so the sequence loop in
			// reassign-objects.sql is what moves them.
			runReassignSuccess(t, "alice_re_idseq", `
			CREATE TABLE alice_re_idseq_tbl (id int GENERATED ALWAYS AS IDENTITY);
			ALTER TABLE alice_re_idseq_tbl OWNER TO "alice_re_idseq";
			ALTER SEQUENCE alice_re_idseq_tbl_id_seq OWNER TO "alice_re_idseq"`)
		})

		t.Run("Reassign: composite row type follows", func(t *testing.T) {
			// Every regular table has an auto-generated composite row type in
			// pg_type (typtype='c', typrelid pointing at the table). Verify
			// must exclude these or it would always fire.
			runReassignSuccess(t, "alice_re_rowtype", `
			CREATE TABLE alice_re_rowtype_tbl (a int, b text, c timestamptz);
			ALTER TABLE alice_re_rowtype_tbl OWNER TO "alice_re_rowtype"`)
		})

		t.Run("Reassign: array type follows", func(t *testing.T) {
			// Every table also has an auto-generated array type (typname
			// '_<tbl>'). Verify must exclude these via the LIKE '\_%' filter.
			runReassignSuccess(t, "alice_re_arr", `
			CREATE TABLE alice_re_arr_tbl (vals int[]);
			ALTER TABLE alice_re_arr_tbl OWNER TO "alice_re_arr"`)
		})

		t.Run("Reassign: FK constraint internal triggers are ignored", func(t *testing.T) {
			// Foreign-key constraints add pg_trigger rows with
			// tgisinternal=true. The safety guard ignores internal triggers,
			// so the tables are still reassigned.
			runReassignSuccess(t, "alice_re_fk", `
			CREATE TABLE alice_re_fk_parent (id int PRIMARY KEY);
			CREATE TABLE alice_re_fk_child (id int REFERENCES alice_re_fk_parent (id));
			ALTER TABLE alice_re_fk_parent OWNER TO "alice_re_fk";
			ALTER TABLE alice_re_fk_child  OWNER TO "alice_re_fk"`)
		})

		t.Run("Reassign: standalone sequence", func(t *testing.T) {
			runReassignSuccess(t, "alice_re_seq", `
			CREATE SEQUENCE alice_re_seq_seq;
			ALTER SEQUENCE alice_re_seq_seq OWNER TO "alice_re_seq"`)
		})

		t.Run("Reassign: custom empty schema", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_re_sch")))
			_, err := bootstrapConn.Exec(t.Context(), `
			CREATE SCHEMA alice_re_sch_schema;
			ALTER SCHEMA alice_re_sch_schema OWNER TO "alice_re_sch"`)
			require.NoError(t, err)
			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_re_sch")))
			require.False(t, userExists(t, adminConn, "alice_re_sch"))
			require.Equal(t, "teleport-object-inheritor", schemaOwner(t, adminConn, "alice_re_sch_schema"))
		})

		t.Run("Reassign: custom schema with contents", func(t *testing.T) {
			runReassignSuccess(t, "alice_re_schtbl", `
			CREATE SCHEMA alice_re_schtbl_schema;
			CREATE TABLE alice_re_schtbl_schema.t (id int);
			ALTER TABLE alice_re_schtbl_schema.t OWNER TO "alice_re_schtbl";
			ALTER SCHEMA alice_re_schtbl_schema OWNER TO "alice_re_schtbl"`)
		})

		t.Run("Reassign: mixed safe types", func(t *testing.T) {
			runReassignSuccess(t, "alice_re_mix", `
			CREATE TABLE alice_re_mix_tbl (id int);
			CREATE SEQUENCE alice_re_mix_seq;
			CREATE SCHEMA alice_re_mix_sch;
			ALTER TABLE alice_re_mix_tbl OWNER TO "alice_re_mix";
			ALTER SEQUENCE alice_re_mix_seq OWNER TO "alice_re_mix";
			ALTER SCHEMA alice_re_mix_sch OWNER TO "alice_re_mix"`)
		})

		// ─ Reassignment refused → user deactivated ──────────────────────────────

		t.Run("Refused: partition child", func(t *testing.T) {
			runReassignRefused(t, "alice_no_pchild", `
			CREATE TABLE alice_no_pchild_parent (id int) PARTITION BY RANGE (id);
			CREATE TABLE alice_no_pchild_p1 PARTITION OF alice_no_pchild_parent
				FOR VALUES FROM (1) TO (10);
			ALTER TABLE alice_no_pchild_p1 OWNER TO "alice_no_pchild"`)
		})

		t.Run("Refused: partitioned parent", func(t *testing.T) {
			runReassignRefused(t, "alice_no_pparent", `
			CREATE TABLE alice_no_pparent_tbl (id int) PARTITION BY RANGE (id);
			ALTER TABLE alice_no_pparent_tbl OWNER TO "alice_no_pparent"`)
		})

		t.Run("Refused: table with row-level security", func(t *testing.T) {
			runReassignRefused(t, "alice_no_rls", `
			CREATE TABLE alice_no_rls_tbl (id int);
			ALTER TABLE alice_no_rls_tbl ENABLE ROW LEVEL SECURITY;
			ALTER TABLE alice_no_rls_tbl OWNER TO "alice_no_rls"`)
		})

		t.Run("Refused: table with SECURITY INVOKER trigger", func(t *testing.T) {
			runReassignRefused(t, "alice_no_tinv", `
			CREATE FUNCTION alice_no_tinv_fn() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RETURN NEW; END $$;
			CREATE TABLE alice_no_tinv_tbl (id int);
			CREATE TRIGGER alice_no_tinv_tg BEFORE INSERT ON alice_no_tinv_tbl
				FOR EACH ROW EXECUTE FUNCTION alice_no_tinv_fn();
			ALTER TABLE alice_no_tinv_tbl OWNER TO "alice_no_tinv"`)
		})

		t.Run("Refused: table with SECURITY DEFINER trigger", func(t *testing.T) {
			runReassignRefused(t, "alice_no_tdef", `
			CREATE FUNCTION alice_no_tdef_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
				BEGIN RETURN NEW; END $$;
			CREATE TABLE alice_no_tdef_tbl (id int);
			CREATE TRIGGER alice_no_tdef_tg BEFORE INSERT ON alice_no_tdef_tbl
				FOR EACH ROW EXECUTE FUNCTION alice_no_tdef_fn();
			ALTER TABLE alice_no_tdef_tbl OWNER TO "alice_no_tdef"`)
		})

		t.Run("Refused: function owned by user", func(t *testing.T) {
			runReassignRefused(t, "alice_no_fn", `
			CREATE FUNCTION alice_no_fn_fn() RETURNS int LANGUAGE sql AS 'SELECT 1';
			ALTER FUNCTION alice_no_fn_fn() OWNER TO "alice_no_fn"`)
		})

		t.Run("Refused: view owned by user", func(t *testing.T) {
			runReassignRefused(t, "alice_no_view", `
			CREATE VIEW alice_no_view_v AS SELECT 1 AS x;
			ALTER VIEW alice_no_view_v OWNER TO "alice_no_view"`)
		})

		t.Run("Refused: materialized view owned by user", func(t *testing.T) {
			runReassignRefused(t, "alice_no_mv", `
			CREATE MATERIALIZED VIEW alice_no_mv_mv AS SELECT 1 AS x;
			ALTER MATERIALIZED VIEW alice_no_mv_mv OWNER TO "alice_no_mv"`)
		})

		t.Run("Refused: foreign table owned by user", func(t *testing.T) {
			runReassignRefused(t, "alice_no_ft", `
			CREATE EXTENSION IF NOT EXISTS postgres_fdw;
			CREATE SERVER alice_no_ft_srv FOREIGN DATA WRAPPER postgres_fdw;
			CREATE FOREIGN TABLE alice_no_ft_ft (id int) SERVER alice_no_ft_srv;
			ALTER FOREIGN TABLE alice_no_ft_ft OWNER TO "alice_no_ft"`)
		})

		t.Run("Refused: standalone composite type", func(t *testing.T) {
			runReassignRefused(t, "alice_no_ct", `
			CREATE TYPE alice_no_ct_t AS (a int, b text);
			ALTER TYPE alice_no_ct_t OWNER TO "alice_no_ct"`)
		})

		t.Run("Refused: domain owned by user", func(t *testing.T) {
			runReassignRefused(t, "alice_no_dom", `
			CREATE DOMAIN alice_no_dom_d AS int;
			ALTER DOMAIN alice_no_dom_d OWNER TO "alice_no_dom"`)
		})

		t.Run("Refused: enum type owned by user", func(t *testing.T) {
			runReassignRefused(t, "alice_no_enum", `
			CREATE TYPE alice_no_enum_e AS ENUM ('a', 'b', 'c');
			ALTER TYPE alice_no_enum_e OWNER TO "alice_no_enum"`)
		})

		t.Run("Refused: public schema owned by user", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_no_pub")))
			var originalOwner string
			err := adminConn.QueryRow(t.Context(),
				`SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'`).Scan(&originalOwner)
			require.NoError(t, err)
			_, err = bootstrapConn.Exec(t.Context(), `ALTER SCHEMA public OWNER TO "alice_no_pub"`)
			require.NoError(t, err)
			t.Cleanup(func() {
				// teleport-admin isn't a member of pg_database_owner (the
				// original owner) and can't restore — bootstrap superuser
				// does it.
				_, _ = bootstrapConn.Exec(context.Background(),
					fmt.Sprintf(`ALTER SCHEMA public OWNER TO %q`, originalOwner))
			})

			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_no_pub")))
			require.True(t, userExists(t, adminConn, "alice_no_pub"))
			require.False(t, canLogin(t, adminConn, "alice_no_pub"))
			require.Equal(t, "alice_no_pub", schemaOwner(t, adminConn, "public"),
				"public schema must not be reassigned")
		})

		// ─ Atomicity ────────────────────────────────────────────────────────────

		t.Run("Refused: mixed reassignable + non-reassignable rolls back", func(t *testing.T) {
			// alice owns a bare table (would be reassigned) AND a function
			// (which the procedure does not touch, and verify catches). The
			// BEGIN/EXCEPTION around CALL teleport_reassign_objects in
			// delete-user.sql rolls the whole reassignment savepoint back;
			// the table must still be owned by alice after the failed delete.
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_atomic")))
			_, err := bootstrapConn.Exec(t.Context(), `
			CREATE TABLE alice_atomic_tbl (id int);
			ALTER TABLE alice_atomic_tbl OWNER TO "alice_atomic";
			CREATE FUNCTION alice_atomic_fn() RETURNS int LANGUAGE sql AS 'SELECT 1';
			ALTER FUNCTION alice_atomic_fn() OWNER TO "alice_atomic"`)
			require.NoError(t, err)

			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_atomic")))
			require.True(t, userExists(t, adminConn, "alice_atomic"))
			require.False(t, canLogin(t, adminConn, "alice_atomic"))
			require.Equal(t, "alice_atomic", tableOwner(t, adminConn, "public", "alice_atomic_tbl"),
				"table ownership must roll back when reassignment is refused")
		})

		// ─ Concurrency ──────────────────────────────────────────────────────────

		t.Run("Reassign: login attempt during reassignment is rejected", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_login_race")))
			_, err := bootstrapConn.Exec(t.Context(), `
			ALTER USER "alice_login_race" WITH PASSWORD 'testpass' LOGIN;
			CREATE TABLE alice_login_race_tbl (id int);
			ALTER TABLE alice_login_race_tbl OWNER TO "alice_login_race"`)
			require.NoError(t, err)

			// Hold AccessShare on the user's table from a session as alice
			// (the table's owner). teleport-admin has no INHERIT on alice
			// in PG16+, so an admin-owned lockConn would not have SELECT.
			// The lock survives the procedure's later NOLOGIN because that
			// only blocks *new* logins.
			lockConn, err := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_login_race:testpass@localhost:%s/postgres", port.Port()))
			require.NoError(t, err)
			defer lockConn.Close(context.Background())
			tx, err := lockConn.Begin(t.Context())
			require.NoError(t, err)
			_, err = tx.Exec(t.Context(), `LOCK TABLE alice_login_race_tbl IN ACCESS SHARE MODE`)
			require.NoError(t, err)

			deleteDone := make(chan error, 1)
			go func() {
				deleteDone <- engine.DeleteUser(t.Context(), reassignSession("alice_login_race"))
			}()

			// Wait until DeleteUser's backend is waiting on the relation lock.
			lockPID := lockConn.PgConn().PID()
			require.Eventually(t, func() bool {
				var n int
				if err := adminConn.QueryRow(t.Context(), `
				SELECT COUNT(*) FROM pg_stat_activity
				WHERE wait_event_type = 'Lock'
				AND wait_event = 'relation'
				AND pid != pg_backend_pid()
				AND pid != $1`, lockPID).Scan(&n); err != nil {
					return false
				}
				return n > 0
			}, 5*time.Second, 50*time.Millisecond, "DeleteUser should be waiting on the relation lock")

			// NOLOGIN was committed by delete-user.sql before reassignment
			// began, so a fresh login attempt must be rejected.
			_, loginErr := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_login_race:testpass@localhost:%s/postgres", port.Port()))
			require.Error(t, loginErr, "login should be rejected while NOLOGIN is in effect")
			require.Contains(t, loginErr.Error(), "not permitted to log in")

			// Release the lock; DeleteUser completes and drops the user.
			require.NoError(t, tx.Commit(t.Context()))
			require.NoError(t, <-deleteDone)
			require.False(t, userExists(t, adminConn, "alice_login_race"))
		})

		t.Run("Reassign: current-db active session bails before reassign", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_re_active")))
			_, err := bootstrapConn.Exec(t.Context(), `
			ALTER USER "alice_re_active" WITH PASSWORD 'testpass' LOGIN;
			CREATE TABLE alice_re_active_tbl (id int);
			ALTER TABLE alice_re_active_tbl OWNER TO "alice_re_active"`)
			require.NoError(t, err)

			userConn, err := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_re_active:testpass@localhost:%s/postgres", port.Port()))
			require.NoError(t, err)
			defer userConn.Close(context.Background())

			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_re_active")))
			require.True(t, userExists(t, adminConn, "alice_re_active"))
			require.True(t, canLogin(t, adminConn, "alice_re_active"),
				"LOGIN should be restored when an active current-db session blocks delete")
			// Table ownership untouched: reassignment never ran.
			require.Equal(t, "alice_re_active", tableOwner(t, adminConn, "public", "alice_re_active_tbl"))
		})

		// ─ Edge cases ───────────────────────────────────────────────────────────

		t.Run("Reassign: user owns nothing", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_re_clean")))
			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_re_clean")))
			require.False(t, userExists(t, adminConn, "alice_re_clean"))
		})

		t.Run("Reassign: other-db active session restores LOGIN", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_re_otherdb")))
			_, err := bootstrapConn.Exec(t.Context(), `
			ALTER USER "alice_re_otherdb" WITH PASSWORD 'testpass' LOGIN;
			CREATE TABLE alice_re_otherdb_tbl (id int);
			ALTER TABLE alice_re_otherdb_tbl OWNER TO "alice_re_otherdb"`)
			require.NoError(t, err)

			// Hold a session in other_db. CONNECT to a newly-created database
			// is granted to PUBLIC by default, so no extra GRANT is needed.
			otherSessionConn, err := pgx.Connect(t.Context(),
				fmt.Sprintf("postgres://alice_re_otherdb:testpass@localhost:%s/other_db", port.Port()))
			require.NoError(t, err)
			defer otherSessionConn.Close(context.Background())

			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_re_otherdb")))
			require.True(t, userExists(t, adminConn, "alice_re_otherdb"))
			require.True(t, canLogin(t, adminConn, "alice_re_otherdb"),
				"LOGIN should be restored when an other-db session blocks drop")
			// Distinct from the current-db case: reassignment ran and committed
			// before the second active-sessions check fired.
			require.Equal(t, "teleport-object-inheritor",
				tableOwner(t, adminConn, "public", "alice_re_otherdb_tbl"))
		})

		t.Run("Refused: object in another database is ignored by dbid filter", func(t *testing.T) {
			require.NoError(t, engine.ActivateUser(t.Context(), reassignSession("alice_re_otherobj")))
			// Create an object owned by alice in other_db. Reassignment in
			// postgres-db must not touch it (dbid filter), and verify must not
			// flag it.
			_, err := bootstrapOtherDBConn.Exec(t.Context(), `
			CREATE TABLE alice_re_otherobj_tbl (id int);
			ALTER TABLE alice_re_otherobj_tbl OWNER TO "alice_re_otherobj"`)
			require.NoError(t, err)

			require.NoError(t, engine.DeleteUser(t.Context(), reassignSession("alice_re_otherobj")))
			// reassign-objects.sql returned cleanly because the dbid filter
			// excluded the other-db object. DROP USER then failed because the
			// cluster-wide pg_shdepend lookup still sees the row, so alice was
			// deactivated.
			require.True(t, userExists(t, adminConn, "alice_re_otherobj"))
			require.False(t, canLogin(t, adminConn, "alice_re_otherobj"))
			// The other-db object is untouched.
			require.Equal(t, "alice_re_otherobj",
				tableOwner(t, otherDBConn, "public", "alice_re_otherobj_tbl"))
		})

	})
}

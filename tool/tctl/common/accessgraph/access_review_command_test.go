/*
 * Teleport
 * Copyright (C) 2026  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package accessgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport"
	accessgraph "github.com/gravitational/teleport/lib/accessgraph/apiclient"
)

// identityAccessPath pins the AG path so a generated-client drift fails the test.
const identityAccessPath = accessGraphAPIPath + "graph/access/v1"

func ptr[T any](v T) *T { return &v }

// findRow returns the first row satisfying pred, or nil.
func findRow(rows [][]string, pred func([]string) bool) []string {
	for _, r := range rows {
		if pred(r) {
			return r
		}
	}
	return nil
}

func TestBuildAccessReviewOutput(t *testing.T) {
	idID := uuid.New()
	resID := uuid.New()
	grStanding := uuid.New()
	grRequest := uuid.New()
	lastAccess := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)

	nodes := []accessgraph.IdentityAccessNode{
		{Id: idID, Name: "alice@corp", Kind: "identity", SubKind: ptr("user")},
		{Id: resID, Name: "prod-db", Kind: "resource", SubKind: ptr("db"), Alias: ptr("Production DB")},
		{Id: grStanding, Name: "admins", Kind: "identity_group", SubKind: ptr("role")},
		{Id: grRequest, Name: "oncall", Kind: "identity_group", SubKind: ptr("access_request"), Temporary: ptr(true)},
	}
	resp := &accessgraph.IdentityAccessResponse{
		Nodes: nodes,
		Data: []accessgraph.IdentityAccessRow{{
			Identity: idID,
			Resources: []accessgraph.IdentityAccessResource{{
				Resource: resID,
				AccessInfo: accessgraph.IdentityAccessDecision{
					Level:         accessgraph.IdentityAccessDecisionLevelStanding,
					Temporary:     ptr(true),
					GrantorCounts: accessgraph.IdentityAccessGrantorCounts{Standing: 1, Request: 1},
					Grantors: []accessgraph.IdentityAccessGrantor{
						{Id: grRequest, Level: accessgraph.IdentityAccessGrantorLevelRequest},
						{Id: grStanding, Level: accessgraph.IdentityAccessGrantorLevelStanding},
					},
					Activity: &accessgraph.IdentityAccessActivity{Count: 14, LastAccess: &lastAccess},
				},
			}},
		}},
	}

	t.Run("resolves nodes and access info", func(t *testing.T) {
		out := buildAccessReviewOutput(resp)
		require.Len(t, out.Identities, 1)

		ia := out.Identities[0]
		require.Equal(t, "alice@corp", ia.Identity.Name)
		require.Equal(t, "user", ia.Identity.SubKind)
		require.Len(t, ia.Resources, 1)

		ra := ia.Resources[0]
		require.Equal(t, "prod-db", ra.Resource.Name)
		require.Equal(t, "Production DB", ra.Resource.Alias)
		require.Equal(t, "standing", ra.Level)
		require.True(t, ra.Temporary)
		require.Equal(t, GrantorCounts{Standing: 1, Request: 1}, ra.GrantorCounts)
		require.Len(t, ra.Grantors, 2)
		require.NotNil(t, ra.Activity)
		require.EqualValues(t, 14, ra.Activity.Count)
		require.Equal(t, &lastAccess, ra.Activity.LastAccess)
	})

	t.Run("primary grantor matches resolved level", func(t *testing.T) {
		out := buildAccessReviewOutput(resp)
		// Grantors are listed request-first, but the resolved level is standing.
		g, ok := primaryGrantor(out.Identities[0].Resources[0])
		require.True(t, ok)
		require.Equal(t, "admins", g.Node.Name)
		require.True(t, g.Node.Temporary == false)
	})

	t.Run("grantor temporary propagates from node", func(t *testing.T) {
		out := buildAccessReviewOutput(resp)
		grantors := out.Identities[0].Resources[0].Grantors
		require.Equal(t, "oncall", grantors[0].Node.Name)
		require.True(t, grantors[0].Node.Temporary)
	})

	t.Run("missing node tolerated", func(t *testing.T) {
		orphan := uuid.New()
		r := &accessgraph.IdentityAccessResponse{
			Nodes: nil,
			Data: []accessgraph.IdentityAccessRow{{
				Identity: orphan,
				Resources: []accessgraph.IdentityAccessResource{{
					Resource:   orphan,
					AccessInfo: accessgraph.IdentityAccessDecision{Level: accessgraph.IdentityAccessDecisionLevelStanding},
				}},
			}},
		}
		out := buildAccessReviewOutput(r)
		require.Equal(t, orphan.String(), out.Identities[0].Identity.ID)
		require.Empty(t, out.Identities[0].Identity.Name)
	})

	t.Run("activity absent when not provided", func(t *testing.T) {
		r := &accessgraph.IdentityAccessResponse{
			Nodes: nodes,
			Data: []accessgraph.IdentityAccessRow{{
				Identity: idID,
				Resources: []accessgraph.IdentityAccessResource{{
					Resource:   resID,
					AccessInfo: accessgraph.IdentityAccessDecision{Level: accessgraph.IdentityAccessDecisionLevelStanding},
				}},
			}},
		}
		out := buildAccessReviewOutput(r)
		require.Nil(t, out.Identities[0].Resources[0].Activity)
	})
}

func TestPrimaryGrantor(t *testing.T) {
	g := func(name, level string) Grantor {
		return Grantor{Node: Node{Name: name}, Level: level}
	}

	t.Run("matches resolved level", func(t *testing.T) {
		ra := ResourceAccess{Level: "standing", Grantors: []Grantor{g("req", "request"), g("std", "standing")}}
		got, ok := primaryGrantor(ra)
		require.True(t, ok)
		require.Equal(t, "std", got.Node.Name)
	})

	t.Run("falls back to first when no level match", func(t *testing.T) {
		ra := ResourceAccess{Level: "denied", Grantors: []Grantor{g("req", "request")}}
		got, ok := primaryGrantor(ra)
		require.True(t, ok)
		require.Equal(t, "req", got.Node.Name)
	})

	t.Run("none when no grantors", func(t *testing.T) {
		_, ok := primaryGrantor(ResourceAccess{Level: "standing"})
		require.False(t, ok)
	})
}

func TestGrantorSummary(t *testing.T) {
	cases := []struct {
		name string
		in   GrantorCounts
		want string
	}{
		{"empty", GrantorCounts{}, ""},
		{"standing only", GrantorCounts{Standing: 2}, "2 standing"},
		{"impersonate only", GrantorCounts{Impersonate: 1}, "1 impersonate"},
		{"mixed in fixed order", GrantorCounts{Standing: 1, Impersonate: 2, Request: 3}, "1 standing, 2 impersonate, 3 request"},
		{"zero levels omitted", GrantorCounts{Standing: 1, Request: 1}, "1 standing, 1 request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, grantorSummary(tc.in))
		})
	}
}

func TestDisplayAccessReviewText(t *testing.T) {
	last := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)
	output := AccessReviewOutput{
		Identities: []IdentityAccess{{
			Identity: Node{ID: "i1", Name: "alice@corp", SubKind: "user"},
			Resources: []ResourceAccess{
				{
					Resource:      Node{Name: "prod-db", SubKind: "db"},
					Level:         "standing",
					GrantorCounts: GrantorCounts{Standing: 1, Request: 1},
					Grantors: []Grantor{
						{Node: Node{Name: "admins"}, Level: "standing"},
						{Node: Node{Name: "break-glass", Temporary: true}, Level: "request"},
					},
					Activity: &Activity{Count: 14, LastAccess: &last},
				},
				{
					Resource:      Node{Name: "prod-web", SubKind: "app"},
					Level:         "request",
					Temporary:     true,
					GrantorCounts: GrantorCounts{Request: 1},
					Grantors:      []Grantor{{Node: Node{Name: "oncall"}, Level: "request"}},
				},
			},
		}},
	}

	t.Run("summary without window omits activity columns", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, displayAccessReviewText(&buf, output, time.Time{}, time.Time{}, false, false))
		out := buf.String()
		require.NotContains(t, out, "Last Access")
		require.NotContains(t, out, "Accesses")
		require.NotContains(t, out, "Period:")
		require.Contains(t, out, "alice@corp")
		require.Contains(t, out, "request*", "temporary access should be marked")
		require.Contains(t, out, "Resource Kind")
		require.Contains(t, out, "db")
		require.Contains(t, out, "app")
		require.NotContains(t, out, "break-glass", "summary shows only the primary grantor")
	})

	t.Run("summary with window shows activity and period", func(t *testing.T) {
		from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		to := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
		var buf bytes.Buffer
		require.NoError(t, displayAccessReviewText(&buf, output, from, to, true, false))
		out := buf.String()
		require.Contains(t, out, "Period:")
		require.Contains(t, out, "Last Access")
		require.Contains(t, out, "14")
		require.Contains(t, out, "never", "resource without activity shows never")
	})

	t.Run("identity cell blanked after first resource row", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, displayAccessReviewText(&buf, output, time.Time{}, time.Time{}, false, false))
		// alice@corp must appear exactly once even though she has two resources.
		require.Equal(t, 1, bytes.Count(buf.Bytes(), []byte("alice@corp")))
	})

	// The detailed view is asserted on its row data, not the rendered string;
	// layout is covered separately by TestBuildAccessTable.
	t.Run("detailed splits a resource with multiple grantors", func(t *testing.T) {
		headers, rows := accessReviewDetailedRows(output, false)
		require.Contains(t, headers, "Grantor Level")
		require.NotContains(t, headers, "Grantor Counts", "detailed drops the path-summary column")
		// prod-db has two grantors → a summary row with no grantor, then one
		// indented row per grantor.
		require.NotNil(t, findRow(rows, func(r []string) bool { return r[2] == "prod-db" && r[5] == "" }),
			"prod-db summary row with no grantor")
		require.NotNil(t, findRow(rows, func(r []string) bool { return r[5] == "↳ admins" }))
		require.NotNil(t, findRow(rows, func(r []string) bool { return r[5] == "↳ break-glass*" }),
			"temporary grantor should be marked")
	})

	t.Run("detailed inlines a sole grantor on the resource row", func(t *testing.T) {
		_, rows := accessReviewDetailedRows(output, false)
		// prod-web's single grantor shares the resource's row, not its own.
		require.NotNil(t, findRow(rows, func(r []string) bool { return r[2] == "prod-web" && r[5] == "oncall" }),
			"sole grantor folded into the resource row")
		require.Nil(t, findRow(rows, func(r []string) bool { return r[5] == "↳ oncall" }),
			"a sole grantor is not split onto its own row")
	})

	t.Run("detailed keeps activity on the summary row for multiple grantors", func(t *testing.T) {
		_, rows := accessReviewDetailedRows(output, true)
		// prod-db's summary row carries the activity; its grantor rows do not.
		summary := findRow(rows, func(r []string) bool { return r[2] == "prod-db" })
		require.NotNil(t, summary)
		require.Equal(t, "14", summary[7], "activity belongs to the resource summary row")
		grantor := findRow(rows, func(r []string) bool { return r[5] == "↳ admins" })
		require.NotNil(t, grantor)
		require.Equal(t, "", grantor[7], "grantor rows must not carry activity")
	})

	t.Run("empty result", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, displayAccessReviewText(&buf, AccessReviewOutput{}, time.Time{}, time.Time{}, false, false))
		require.Contains(t, buf.String(), "No access found.")
	})

	t.Run("warnings printed", func(t *testing.T) {
		var buf bytes.Buffer
		o := AccessReviewOutput{Warnings: []string{"activity unavailable: boom"}}
		require.NoError(t, displayAccessReviewText(&buf, o, time.Time{}, time.Time{}, false, false))
		require.Contains(t, buf.String(), "Warning: activity unavailable: boom")
	})
}

// TestBuildAccessTable pins the layout policy: every column renders in full
// when the table fits the terminal, and only the Resource column is ever
// bounded — so naturally wide columns like Grantor Counts and Last Access are never
// truncated just because the table has many columns.
func TestBuildAccessTable(t *testing.T) {
	headers := []string{"Identity", "Kind", "Resource", "Resource Kind", "Access Level", "Granted By", "Grantor Counts", "Accesses", "Last Access"}
	rows := [][]string{
		{"ghassan", "user", "teleport-mcp-demo", "app", "standing", "Local DB ACL", "3 standing, 1 request", "6", "2026-06-05T19:15:32-07:00"},
	}

	t.Run("wide terminal renders every column in full", func(t *testing.T) {
		table := buildAccessTable(headers, rows, 200)
		out := table.String()
		require.NotContains(t, out, "...", "nothing should truncate when the table fits the terminal")
		require.Contains(t, out, "3 standing, 1 request")
		require.Contains(t, out, "2026-06-05T19:15:32-07:00")
		require.Contains(t, out, "teleport-mcp-demo")
	})

	t.Run("narrow terminal bounds only the Resource column", func(t *testing.T) {
		longResource := strings.Repeat("x", 80)
		narrowRows := [][]string{
			{"ghassan", "user", longResource, "app", "standing", "Local DB ACL", "3 standing, 1 request", "6", "2026-06-05T19:15:32-07:00"},
		}
		table := buildAccessTable(headers, narrowRows, 60)
		out := table.String()
		// The wide non-resource columns stay intact even on a narrow terminal...
		require.Contains(t, out, "3 standing, 1 request")
		require.Contains(t, out, "2026-06-05T19:15:32-07:00")
		// ...while the oversized Resource name is the only thing truncated.
		require.NotContains(t, out, longResource, "an oversized resource name should be bounded")
		require.Contains(t, out, "...")
	})
}

// accessPageHandler serves the configured response pages in order, recording
// the iterator the client sent on each call.
func accessPageHandler(t *testing.T, pages []accessgraph.IdentityAccessResponse) (http.Handler, *[]string) {
	t.Helper()
	var (
		calls     atomic.Int64
		iterators []string
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(calls.Add(1) - 1)
		require.Equal(t, identityAccessPath, r.URL.Path, "generated client drifted from the AG access path")
		iterators = append(iterators, r.URL.Query().Get("iterator"))
		require.Less(t, idx, len(pages), "client requested more pages than configured")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		require.NoError(t, json.NewEncoder(w).Encode(pages[idx]))
	})
	return h, &iterators
}

func TestFetchIdentityAccess(t *testing.T) {
	row := func() accessgraph.IdentityAccessRow {
		return accessgraph.IdentityAccessRow{Identity: uuid.New()}
	}
	baseParams := accessgraph.ListIdentityAccessParams{Query: "SELECT * FROM access_path"}

	t.Run("single page, no cursor", func(t *testing.T) {
		h, iters := accessPageHandler(t, []accessgraph.IdentityAccessResponse{
			{Data: []accessgraph.IdentityAccessRow{row()}},
		})
		c := newAccessGraphTestClient(t, h)
		resp, truncated, err := fetchIdentityAccess(context.Background(), c, baseParams, 100)
		require.NoError(t, err)
		require.False(t, truncated)
		require.Len(t, resp.Data, 1)
		require.Equal(t, []string{""}, *iters, "first call must omit the iterator")
	})

	t.Run("walks the cursor across pages and dedups nodes", func(t *testing.T) {
		shared := accessgraph.IdentityAccessNode{Id: uuid.New(), Name: "shared", Kind: "identity"}
		h, iters := accessPageHandler(t, []accessgraph.IdentityAccessResponse{
			{Data: []accessgraph.IdentityAccessRow{row()}, Nodes: []accessgraph.IdentityAccessNode{shared}, NextCursor: ptr("c1")},
			{Data: []accessgraph.IdentityAccessRow{row()}, Nodes: []accessgraph.IdentityAccessNode{shared}, NextCursor: ptr("c2")},
			{Data: []accessgraph.IdentityAccessRow{row()}},
		})
		c := newAccessGraphTestClient(t, h)
		resp, truncated, err := fetchIdentityAccess(context.Background(), c, baseParams, 100)
		require.NoError(t, err)
		require.False(t, truncated)
		require.Len(t, resp.Data, 3)
		require.Len(t, resp.Nodes, 1, "shared node must be deduplicated")
		require.Equal(t, []string{"", "c1", "c2"}, *iters)
	})

	t.Run("truncates at maxResults", func(t *testing.T) {
		h, _ := accessPageHandler(t, []accessgraph.IdentityAccessResponse{
			{Data: []accessgraph.IdentityAccessRow{row(), row(), row()}, NextCursor: ptr("more")},
		})
		c := newAccessGraphTestClient(t, h)
		resp, truncated, err := fetchIdentityAccess(context.Background(), c, baseParams, 2)
		require.NoError(t, err)
		require.True(t, truncated)
		require.Len(t, resp.Data, 2)
	})

	t.Run("non-advancing cursor stops pagination", func(t *testing.T) {
		h, _ := accessPageHandler(t, []accessgraph.IdentityAccessResponse{
			{Data: []accessgraph.IdentityAccessRow{row()}, NextCursor: ptr("stuck")},
			{Data: []accessgraph.IdentityAccessRow{row()}, NextCursor: ptr("stuck")},
		})
		c := newAccessGraphTestClient(t, h)
		resp, truncated, err := fetchIdentityAccess(context.Background(), c, baseParams, 100)
		require.NoError(t, err)
		require.True(t, truncated)
		require.Len(t, resp.Data, 1)
	})

	t.Run("iac_error propagated", func(t *testing.T) {
		h, _ := accessPageHandler(t, []accessgraph.IdentityAccessResponse{
			{Data: []accessgraph.IdentityAccessRow{row()}, IacError: ptr("activity center down")},
		})
		c := newAccessGraphTestClient(t, h)
		resp, _, err := fetchIdentityAccess(context.Background(), c, baseParams, 100)
		require.NoError(t, err)
		require.NotNil(t, resp.IacError)
		require.Equal(t, "activity center down", *resp.IacError)
	})
}

func TestAccessReviewFlags(t *testing.T) {
	newApp := func() (*kingpin.Application, *AccessGraphCommand) {
		app := kingpin.New("tctl", "")
		app.Terminate(nil)
		c := &AccessGraphCommand{}
		c.initAccessReview(app)
		return app, c
	}

	t.Run("defaults", func(t *testing.T) {
		app, c := newApp()
		_, err := app.Parse([]string{"access-review", "--query", "SELECT * FROM access_path"})
		require.NoError(t, err)
		require.Equal(t, "SELECT * FROM access_path", c.accessReview.query)
		require.Equal(t, 50, c.accessReview.limit)
		require.Equal(t, teleport.Text, c.accessReview.format)
		require.True(t, c.accessReview.from.IsZero())
		require.True(t, c.accessReview.to.IsZero())
	})

	t.Run("query required", func(t *testing.T) {
		app, _ := newApp()
		_, err := app.Parse([]string{"access-review"})
		require.Error(t, err)
	})
}

func TestAccessReviewValidation(t *testing.T) {
	// Returns an empty page so the happy path renders "No access found." without
	// the validation cases ever reaching the network.
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[],"nodes":[]}`))
	})
	client := newAccessGraphTestClient(t, h)

	run := func(args accessReviewArgs) (string, error) {
		var buf bytes.Buffer
		c := &AccessGraphCommand{stdout: &buf, accessReview: args}
		err := c.AccessReview(context.Background(), client)
		return buf.String(), err
	}
	base := accessReviewArgs{query: "SELECT * FROM access_path", limit: 50, format: teleport.Text}

	t.Run("limit below range", func(t *testing.T) {
		args := base
		args.limit = 0
		_, err := run(args)
		require.True(t, trace.IsBadParameter(err), "want BadParameter, got %v", err)
	})

	t.Run("--to without --from", func(t *testing.T) {
		args := base
		args.to = time.Now()
		_, err := run(args)
		require.True(t, trace.IsBadParameter(err), "want BadParameter, got %v", err)
	})

	t.Run("--from in the future is rejected", func(t *testing.T) {
		args := base
		args.from = time.Now().Add(time.Hour)
		_, err := run(args)
		require.True(t, trace.IsBadParameter(err), "want BadParameter, got %v", err)
	})

	t.Run("valid no-window review renders", func(t *testing.T) {
		out, err := run(base)
		require.NoError(t, err)
		require.Contains(t, out, "No access found.")
	})
}

CREATE OR REPLACE PROCEDURE pg_temp.teleport_reassign_objects(source_user varchar, destination_user varchar)
LANGUAGE plpgsql
AS $$
DECLARE
    user_oid oid;
    current_db_oid oid;
    obj record;
    remaining_objects text[];
BEGIN
    SELECT oid INTO user_oid FROM pg_roles WHERE rolname = source_user;
    IF user_oid IS NULL THEN
        RAISE WARNING 'User % not found, skipping object reassignment', source_user;
        RETURN;
    END IF;

    SELECT oid INTO current_db_oid FROM pg_database WHERE datname = current_database();

    -- Reassign safe tables: regular tables that are not partition children,
    -- do not have row-level security enabled, and have no user-defined
    -- triggers. Internal triggers (e.g. foreign-key constraint triggers) are
    -- ignored. ALTER TABLE OWNER TO also reassigns the table's indexes,
    -- TOAST table, composite row type, and identity sequences.
    FOR obj IN
        SELECT n.nspname, c.relname
        FROM pg_shdepend sd
        JOIN pg_class c ON c.oid = sd.objid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE sd.refobjid = user_oid
        AND sd.refclassid = 'pg_authid'::regclass
        AND sd.deptype = 'o'
        AND sd.dbid = current_db_oid
        AND sd.classid = 'pg_class'::regclass
        AND c.relkind = 'r'
        AND NOT c.relispartition
        AND NOT c.relrowsecurity
        AND NOT EXISTS (
            SELECT 1 FROM pg_trigger tg
            WHERE tg.tgrelid = c.oid
            AND NOT tg.tgisinternal
        )
    LOOP
        EXECUTE FORMAT('ALTER TABLE %I.%I OWNER TO %I',
            obj.nspname, obj.relname, destination_user);
    END LOOP;

    -- Reassign standalone sequences. Sequences attached to a table are
    -- already reassigned by ALTER TABLE above.
    FOR obj IN
        SELECT n.nspname, c.relname
        FROM pg_shdepend sd
        JOIN pg_class c ON c.oid = sd.objid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE sd.refobjid = user_oid
        AND sd.refclassid = 'pg_authid'::regclass
        AND sd.deptype = 'o'
        AND sd.dbid = current_db_oid
        AND sd.classid = 'pg_class'::regclass
        AND c.relkind = 'S'
    LOOP
        EXECUTE FORMAT('ALTER SEQUENCE %I.%I OWNER TO %I',
            obj.nspname, obj.relname, destination_user);
    END LOOP;

    -- Reassign safe schemas. The "public" schema sits in most users'
    -- default search_path, so transferring it to teleport-object-inheritor
    -- would let any member plant shadow objects. System schemas are a
    -- sanity check.
    FOR obj IN
        SELECT n.nspname
        FROM pg_shdepend sd
        JOIN pg_namespace n ON n.oid = sd.objid
        WHERE sd.refobjid = user_oid
        AND sd.refclassid = 'pg_authid'::regclass
        AND sd.deptype = 'o'
        AND sd.dbid = current_db_oid
        AND sd.classid = 'pg_namespace'::regclass
        AND n.nspname != 'public'
        AND n.nspname NOT LIKE 'pg_%'
        AND n.nspname != 'information_schema'
    LOOP
        EXECUTE FORMAT('ALTER SCHEMA %I OWNER TO %I',
            obj.nspname, destination_user);
    END LOOP;

    -- Verify the user no longer owns anything. Composite row types and
    -- array types follow their base type, so they are excluded — the base
    -- type's reassignment will have moved them along with it.
    SELECT ARRAY_AGG(
        COALESCE(c.relname, n.nspname, p.proname, t.typname, sd.objid::text)
        ORDER BY 1
    ) INTO remaining_objects
    FROM pg_shdepend sd
    LEFT JOIN pg_class     c ON sd.classid = 'pg_class'::regclass     AND c.oid = sd.objid
    LEFT JOIN pg_namespace n ON sd.classid = 'pg_namespace'::regclass AND n.oid = sd.objid
    LEFT JOIN pg_proc      p ON sd.classid = 'pg_proc'::regclass      AND p.oid = sd.objid
    LEFT JOIN pg_type      t ON sd.classid = 'pg_type'::regclass      AND t.oid = sd.objid
    WHERE sd.refobjid = user_oid
    AND sd.refclassid = 'pg_authid'::regclass
    AND sd.deptype = 'o'
    AND sd.dbid = current_db_oid
    AND NOT (
        sd.classid = 'pg_type'::regclass AND (
            (t.typtype = 'c' AND t.typrelid != 0)
            OR t.typname LIKE '\_%'
        )
    );

    IF remaining_objects IS NOT NULL THEN
        RAISE EXCEPTION 'User % still owns object(s) after reassignment: %',
            source_user, array_to_string(remaining_objects, ', ');
    END IF;
END;$$;

-- ============================================================
-- PropGuard AI — Row-Level Security (RLS) Policies
-- ============================================================
-- Per PRD Security Checklist:
--   "PostgreSQL row-level security (RLS) ensures users can only
--    read/write their own emergency contact profiles and document
--    audit history."
--
-- Run this after your Alembic migrations have created the tables.
-- The FastAPI app connects as `propguard_app` (a non-superuser role)
-- and sets `app.current_uid` per-request via SET LOCAL, so Postgres
-- itself enforces isolation as defense-in-depth beneath the app-layer
-- `WHERE user_id = :uid` filters already in every router.
-- ============================================================

-- 1. Dedicated least-privilege app role (superusers bypass RLS entirely).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'propguard_app') THEN
    CREATE ROLE propguard_app LOGIN PASSWORD 'CHANGE_ME_DO_NOT_COMMIT';
  END IF;
END
$$;

GRANT CONNECT ON DATABASE propguard_db TO propguard_app;
GRANT USAGE ON SCHEMA public TO propguard_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO propguard_app;

-- 2. Enable RLS on every user-scoped table.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE property_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE intercepted_spam ENABLE ROW LEVEL SECURITY;
ALTER TABLE sos_logs ENABLE ROW LEVEL SECURITY;

-- Force RLS even for the table owner role (belt-and-suspenders).
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE property_audits FORCE ROW LEVEL SECURITY;
ALTER TABLE intercepted_spam FORCE ROW LEVEL SECURITY;
ALTER TABLE sos_logs FORCE ROW LEVEL SECURITY;

-- 3. Policies: a row is visible/writable only when its owner matches the
--    uid the app set for this request via:
--      SET LOCAL app.current_uid = '<firebase-uid>';
--    (wire this into app/database.py's get_db() dependency, right after
--    opening the session, using the uid from get_current_user()).

CREATE POLICY users_self_access ON users
  USING (id = current_setting('app.current_uid', true))
  WITH CHECK (id = current_setting('app.current_uid', true));

CREATE POLICY property_audits_owner_access ON property_audits
  USING (user_id = current_setting('app.current_uid', true))
  WITH CHECK (user_id = current_setting('app.current_uid', true));

CREATE POLICY intercepted_spam_owner_access ON intercepted_spam
  USING (user_id = current_setting('app.current_uid', true))
  WITH CHECK (user_id = current_setting('app.current_uid', true));

CREATE POLICY sos_logs_owner_access ON sos_logs
  USING (user_id = current_setting('app.current_uid', true))
  WITH CHECK (user_id = current_setting('app.current_uid', true));

-- ============================================================
-- Wiring note for app/database.py:
--
--   async def get_db_scoped(user: dict = Depends(get_current_user)):
--       async with AsyncSessionLocal() as session:
--           await session.execute(
--               text("SET LOCAL app.current_uid = :uid"),
--               {"uid": user["uid"]},
--           )
--           yield session
--
-- Swap this in as the `db` dependency on any route that should be
-- RLS-protected at the database layer in addition to the existing
-- application-layer `WHERE user_id = ...` filters.
-- ============================================================

-- ============================================================================
-- ZAHA AI Virtual Try-On - PostgreSQL Schema (Render, Railway, etc.)
--
-- How to run:
-- 1. Render: Dashboard → PostgreSQL → Connect → run this in "Shell" or use psql with Internal/External URL.
-- 2. Railway: Connect to your Postgres, then run this SQL in the Query tab.
-- 3. Local: psql $DATABASE_URL -f database/schema.pg.sql
--
-- Set DATABASE_URL in your app (Render sets it automatically when you add a Postgres instance).
-- ============================================================================

-- Role type for users
DO $$ BEGIN
  CREATE TYPE user_role AS ENUM ('user', 'superadmin');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

-- ----------------------------------------------------------------------------
-- Users: email login and role
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role user_role NOT NULL DEFAULT 'user',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Try-On History: each generation tied to a user
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS try_on_history (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  generation_id BIGINT NOT NULL,
  person_filename VARCHAR(255) NOT NULL,
  product_filename VARCHAR(255) NOT NULL,
  result_filenames JSONB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_try_on_history_user_id ON try_on_history(user_id);
CREATE INDEX IF NOT EXISTS idx_try_on_history_created_at ON try_on_history(created_at);
CREATE INDEX IF NOT EXISTS idx_try_on_history_generation_id ON try_on_history(generation_id);

-- ZAHA AI — Plugin, Promo Codes & Credits (PostgreSQL)
-- Run after schema.pg.sql: psql $DATABASE_URL -f database/schema-plugin.pg.sql

-- Promo codes (admin-created, user redeems for try-on credits)
CREATE TABLE IF NOT EXISTS promo_codes (
  id SERIAL PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  try_on_credits INTEGER NOT NULL DEFAULT 1,
  max_redemptions INTEGER NOT NULL DEFAULT 1,
  times_redeemed INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMP NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  notes TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_promo_codes_code ON promo_codes (UPPER(code));

-- CMS plugin site registrations (WordPress / Shopify)
CREATE TABLE IF NOT EXISTS plugin_sites (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  platform VARCHAR(32) NOT NULL DEFAULT 'wordpress',
  api_key VARCHAR(128) NOT NULL UNIQUE,
  allowed_domains TEXT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- End-user session after promo redeem (works without ZAHA login)
CREATE TABLE IF NOT EXISTS plugin_sessions (
  id SERIAL PRIMARY KEY,
  token VARCHAR(128) NOT NULL UNIQUE,
  site_id INTEGER NOT NULL REFERENCES plugin_sites(id) ON DELETE CASCADE,
  promo_code_id INTEGER NULL REFERENCES promo_codes(id) ON DELETE SET NULL,
  credits_remaining INTEGER NOT NULL DEFAULT 0,
  customer_email VARCHAR(255) NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_plugin_sessions_token ON plugin_sessions(token);

-- Promo redemption audit
CREATE TABLE IF NOT EXISTS promo_redemptions (
  id SERIAL PRIMARY KEY,
  promo_code_id INTEGER NOT NULL REFERENCES promo_codes(id) ON DELETE CASCADE,
  plugin_session_id INTEGER NULL REFERENCES plugin_sessions(id) ON DELETE SET NULL,
  user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  credits_granted INTEGER NOT NULL,
  redeemed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Logged-in user credit balance (optional, stacked with promo)
CREATE TABLE IF NOT EXISTS user_credits (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  credits_remaining INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Extend try-on history for plugin sessions
ALTER TABLE try_on_history ADD COLUMN IF NOT EXISTS plugin_session_id INTEGER NULL REFERENCES plugin_sessions(id) ON DELETE SET NULL;
ALTER TABLE try_on_history ALTER COLUMN user_id DROP NOT NULL;

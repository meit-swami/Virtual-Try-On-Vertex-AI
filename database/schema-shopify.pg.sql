-- ZAHA AI — Shopify App (OAuth, billing) — PostgreSQL
-- Run after schema.pg.sql and schema-plugin.pg.sql.

-- One row per installed Shopify store.
CREATE TABLE IF NOT EXISTS shopify_shops (
  id SERIAL PRIMARY KEY,
  shop_domain VARCHAR(255) NOT NULL UNIQUE,      -- e.g. my-store.myshopify.com
  access_token TEXT NOT NULL,                     -- Admin API offline token
  scope VARCHAR(512) NULL,
  -- Link to the plugin_sites row auto-provisioned for this shop (holds api_key)
  plugin_site_id INTEGER NULL REFERENCES plugin_sites(id) ON DELETE SET NULL,
  -- Billing
  plan VARCHAR(64) NOT NULL DEFAULT 'free',       -- free | starter | pro | ...
  charge_id VARCHAR(64) NULL,                      -- Shopify RecurringApplicationCharge id
  billing_status VARCHAR(32) NOT NULL DEFAULT 'none', -- none | pending | active | cancelled
  installed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  uninstalled_at TIMESTAMP NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_shopify_shops_domain ON shopify_shops(shop_domain);

-- Short-lived OAuth nonces (state) to defend against CSRF during install.
CREATE TABLE IF NOT EXISTS shopify_oauth_nonces (
  id SERIAL PRIMARY KEY,
  shop_domain VARCHAR(255) NOT NULL,
  nonce VARCHAR(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_shopify_nonces_nonce ON shopify_oauth_nonces(nonce);

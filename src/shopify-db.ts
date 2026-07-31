// Shopify shop persistence (PostgreSQL). Mirrors the style of plugin-db.ts.
import './env';
import { pool, isPostgres } from './db';

function pg() {
    if (!isPostgres || !pool) throw new Error('Shopify app requires PostgreSQL (DATABASE_URL).');
    return pool as import('pg').Pool;
}

export interface ShopifyShop {
    id: number;
    shop_domain: string;
    access_token: string;
    scope: string | null;
    plugin_site_id: number | null;
    plan: string;
    charge_id: string | null;
    billing_status: string;
    is_active: boolean;
}

export async function runShopifyMigrations(): Promise<void> {
    if (!isPostgres || !pool) return;
    const fs = await import('fs');
    const path = await import('path');
    const sqlPath = path.join(process.cwd(), 'database', 'schema-shopify.pg.sql');
    if (!fs.existsSync(sqlPath)) return;
    await pg().query(fs.readFileSync(sqlPath, 'utf8'));
}

export async function getShopByDomain(shopDomain: string): Promise<ShopifyShop | null> {
    const r = await pg().query('SELECT * FROM shopify_shops WHERE shop_domain = $1', [shopDomain]);
    return (r.rows[0] as ShopifyShop) ?? null;
}

/** Insert or update a shop after a successful OAuth token exchange. */
export async function upsertShop(
    shopDomain: string,
    accessToken: string,
    scope: string | null,
    pluginSiteId: number | null
): Promise<ShopifyShop> {
    const r = await pg().query(
        `INSERT INTO shopify_shops (shop_domain, access_token, scope, plugin_site_id, is_active, uninstalled_at)
         VALUES ($1, $2, $3, $4, TRUE, NULL)
         ON CONFLICT (shop_domain) DO UPDATE
           SET access_token = EXCLUDED.access_token,
               scope = EXCLUDED.scope,
               plugin_site_id = COALESCE(shopify_shops.plugin_site_id, EXCLUDED.plugin_site_id),
               is_active = TRUE,
               uninstalled_at = NULL
         RETURNING *`,
        [shopDomain, accessToken, scope, pluginSiteId]
    );
    return r.rows[0] as ShopifyShop;
}

export async function setShopBilling(
    shopDomain: string,
    plan: string,
    chargeId: string | null,
    billingStatus: string
): Promise<void> {
    await pg().query(
        'UPDATE shopify_shops SET plan = $2, charge_id = $3, billing_status = $4 WHERE shop_domain = $1',
        [shopDomain, plan, chargeId, billingStatus]
    );
}

export async function markShopUninstalled(shopDomain: string): Promise<void> {
    await pg().query(
        'UPDATE shopify_shops SET is_active = FALSE, uninstalled_at = CURRENT_TIMESTAMP, billing_status = $2 WHERE shop_domain = $1',
        [shopDomain, 'cancelled']
    );
}

/** Return the auto-provisioned plugin API key for an installed, active shop. */
export async function getShopApiKey(shopDomain: string): Promise<string | null> {
    const r = await pg().query(
        `SELECT ps.api_key
           FROM shopify_shops s
           JOIN plugin_sites ps ON ps.id = s.plugin_site_id
          WHERE s.shop_domain = $1 AND s.is_active = TRUE AND ps.is_active = TRUE`,
        [shopDomain]
    );
    return (r.rows[0]?.api_key as string) ?? null;
}

export async function saveNonce(shopDomain: string, nonce: string): Promise<void> {
    await pg().query('INSERT INTO shopify_oauth_nonces (shop_domain, nonce) VALUES ($1, $2)', [shopDomain, nonce]);
}

/** Consume a nonce (single-use). Returns true if it existed for this shop. */
export async function consumeNonce(shopDomain: string, nonce: string): Promise<boolean> {
    const r = await pg().query(
        'DELETE FROM shopify_oauth_nonces WHERE shop_domain = $1 AND nonce = $2 RETURNING id',
        [shopDomain, nonce]
    );
    return (r.rowCount ?? 0) > 0;
}

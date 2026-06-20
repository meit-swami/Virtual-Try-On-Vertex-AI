import crypto from 'crypto';
import { pool } from './db';

const usePostgres = !!process.env.DATABASE_URL;

function toPgParams(sql: string): string {
    let n = 0;
    return sql.replace(/\?/g, () => `$${++n}`);
}

async function query<T>(sql: string, params?: unknown[]): Promise<T> {
    if (usePostgres && pool) {
        const result = await (pool as import('pg').Pool).query(toPgParams(sql), params ?? []);
        return result.rows as T;
    }
    throw new Error('Plugin features require PostgreSQL (DATABASE_URL).');
}

export interface PromoCode {
    id: number;
    code: string;
    try_on_credits: number;
    max_redemptions: number;
    times_redeemed: number;
    expires_at: Date | null;
    is_active: boolean;
    notes: string | null;
    created_at: Date;
}

export interface PluginSite {
    id: number;
    name: string;
    platform: string;
    api_key: string;
    allowed_domains: string | null;
    is_active: boolean;
    created_at: Date;
}

export interface PluginSession {
    id: number;
    token: string;
    site_id: number;
    promo_code_id: number | null;
    credits_remaining: number;
    customer_email: string | null;
    expires_at: Date;
    created_at: Date;
}

export function generateApiKey(): string {
    return 'zaha_' + crypto.randomBytes(24).toString('hex');
}

export function generateSessionToken(): string {
    return 'sess_' + crypto.randomBytes(32).toString('hex');
}

export async function runPluginMigrations(): Promise<void> {
    if (!usePostgres || !pool) return;
    const fs = await import('fs');
    const path = await import('path');
    const sqlPath = path.join(process.cwd(), 'database', 'schema-plugin.pg.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    await (pool as import('pg').Pool).query(sql);
}

export async function getPluginSiteByApiKey(apiKey: string): Promise<PluginSite | null> {
    const rows = await query<PluginSite[]>('SELECT * FROM plugin_sites WHERE api_key = ? AND is_active = TRUE', [apiKey]);
    return rows[0] ?? null;
}

export async function getPluginSessionByToken(token: string): Promise<PluginSession | null> {
    const rows = await query<PluginSession[]>(
        'SELECT * FROM plugin_sessions WHERE token = ? AND expires_at > NOW()',
        [token]
    );
    return rows[0] ?? null;
}

export async function getPromoByCode(code: string): Promise<PromoCode | null> {
    const rows = await query<PromoCode[]>(
        'SELECT * FROM promo_codes WHERE UPPER(code) = UPPER(?) AND is_active = TRUE',
        [code.trim()]
    );
    return rows[0] ?? null;
}

export async function listPromoCodes(): Promise<PromoCode[]> {
    return query<PromoCode[]>('SELECT * FROM promo_codes ORDER BY created_at DESC');
}

export async function createPromoCode(data: {
    code: string;
    try_on_credits: number;
    max_redemptions: number;
    expires_at?: string | null;
    notes?: string | null;
}): Promise<PromoCode> {
    const code = data.code.trim().toUpperCase();
    if (usePostgres && pool) {
        const result = await (pool as import('pg').Pool).query(
            `INSERT INTO promo_codes (code, try_on_credits, max_redemptions, expires_at, notes)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [code, data.try_on_credits, data.max_redemptions, data.expires_at ?? null, data.notes ?? null]
        );
        return result.rows[0] as PromoCode;
    }
    throw new Error('No database configured.');
}

export async function updatePromoCode(
    id: number,
    data: Partial<{ try_on_credits: number; max_redemptions: number; expires_at: string | null; is_active: boolean; notes: string | null }>
): Promise<PromoCode | null> {
    const fields: string[] = [];
    const values: unknown[] = [];
    let i = 1;
    for (const [key, val] of Object.entries(data)) {
        if (val !== undefined) {
            fields.push(`${key} = $${i++}`);
            values.push(val);
        }
    }
    if (fields.length === 0) return null;
    values.push(id);
    const result = await (pool as import('pg').Pool).query(
        `UPDATE promo_codes SET ${fields.join(', ')} WHERE id = $${i} RETURNING *`,
        values
    );
    return (result.rows[0] as PromoCode) ?? null;
}

export async function deletePromoCode(id: number): Promise<boolean> {
    const result = await (pool as import('pg').Pool).query('DELETE FROM promo_codes WHERE id = $1', [id]);
    return (result.rowCount ?? 0) > 0;
}

export async function redeemPromoForPlugin(
    siteId: number,
    promo: PromoCode,
    customerEmail?: string | null
): Promise<PluginSession> {
    if (promo.expires_at && new Date(promo.expires_at) < new Date()) {
        throw new Error('This promo code has expired.');
    }
    if (promo.times_redeemed >= promo.max_redemptions) {
        throw new Error('This promo code has reached its redemption limit.');
    }

    const token = generateSessionToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const pg = pool as import('pg').Pool;
    const client = await pg.connect();
    try {
        await client.query('BEGIN');
        const sess = await client.query(
            `INSERT INTO plugin_sessions (token, site_id, promo_code_id, credits_remaining, customer_email, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [token, siteId, promo.id, promo.try_on_credits, customerEmail ?? null, expiresAt]
        );
        await client.query('UPDATE promo_codes SET times_redeemed = times_redeemed + 1 WHERE id = $1', [promo.id]);
        await client.query(
            'INSERT INTO promo_redemptions (promo_code_id, plugin_session_id, credits_granted) VALUES ($1, $2, $3)',
            [promo.id, sess.rows[0].id, promo.try_on_credits]
        );
        await client.query('COMMIT');
        return sess.rows[0] as PluginSession;
    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }
}

export async function deductPluginCredit(sessionId: number): Promise<number> {
    const result = await (pool as import('pg').Pool).query(
        `UPDATE plugin_sessions SET credits_remaining = credits_remaining - 1
         WHERE id = $1 AND credits_remaining > 0
         RETURNING credits_remaining`,
        [sessionId]
    );
    if (result.rowCount === 0) throw new Error('No try-on credits remaining. Redeem a promo code.');
    return result.rows[0].credits_remaining as number;
}

export async function insertPluginTryOnHistory(
    pluginSessionId: number,
    generationId: number,
    personFilename: string,
    productFilename: string,
    resultFilenames: string[]
): Promise<number> {
    const json = JSON.stringify(resultFilenames);
    const result = await (pool as import('pg').Pool).query(
        `INSERT INTO try_on_history (plugin_session_id, generation_id, person_filename, product_filename, result_filenames)
         VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id`,
        [pluginSessionId, generationId, personFilename, productFilename, json]
    );
    return result.rows[0]?.id ?? 0;
}

export async function countPluginSites(): Promise<number> {
    const rows = await query<{ cnt: string }[]>('SELECT COUNT(*) AS cnt FROM plugin_sites');
    return parseInt(rows[0]?.cnt ?? '0', 10);
}

export async function createPluginSite(name: string, platform: string, allowedDomains?: string): Promise<PluginSite> {
    const apiKey = generateApiKey();
    const result = await (pool as import('pg').Pool).query(
        `INSERT INTO plugin_sites (name, platform, api_key, allowed_domains) VALUES ($1, $2, $3, $4) RETURNING *`,
        [name, platform, apiKey, allowedDomains ?? null]
    );
    return result.rows[0] as PluginSite;
}

export async function listPluginSites(): Promise<PluginSite[]> {
    return query<PluginSite[]>('SELECT * FROM plugin_sites ORDER BY created_at DESC');
}

export async function seedDefaultPromoAndSite(): Promise<void> {
    const promos = await listPromoCodes();
    if (!promos.some((p) => p.code.toUpperCase() === 'MEITANSHI7992')) {
        await createPromoCode({
            code: 'MEITANSHI7992',
            try_on_credits: 20,
            max_redemptions: 100,
            notes: 'Test promo — 20 try-ons per redemption',
        });
        console.log('🎟️  Promo code seeded: MEITANSHI7992 (20 try-ons, up to 100 redemptions)');
    }
    const siteCount = await countPluginSites();
    if (siteCount === 0) {
        const site = await createPluginSite('Local Dev Store', 'wordpress', 'localhost,indianvirasat.com');
        console.log(`🔌 Plugin API key (save for WordPress/Shopify): ${site.api_key}`);
    }
}

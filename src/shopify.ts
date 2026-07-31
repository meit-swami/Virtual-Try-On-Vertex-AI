// ============================================================================
// Shopify App — OAuth install, mandatory webhooks (GDPR + uninstall), Billing
// API, and a signed App Proxy config endpoint. Extends the existing Express
// server so there is a single ZAHA codebase.
//
// Required env:
//   SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_APP_URL (public https URL)
// Optional:
//   SHOPIFY_SCOPES (default "read_products")
//   SHOPIFY_API_VERSION (default "2024-10")
//   SHOPIFY_BILLING_ENABLED ("true" to require a subscription after install)
//   SHOPIFY_PLAN_NAME, SHOPIFY_PLAN_PRICE, SHOPIFY_PLAN_TRIAL_DAYS,
//   SHOPIFY_BILLING_TEST ("true" for test charges during development)
// ============================================================================

import crypto from 'crypto';
import { Express, Request, Response } from 'express';
import { httpsRequest } from './gcp-auth';
import { createPluginSite } from './plugin-db';
import {
    upsertShop,
    getShopByDomain,
    setShopBilling,
    markShopUninstalled,
    saveNonce,
    consumeNonce,
    getShopApiKey,
} from './shopify-db';

const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-10';
const SCOPES = process.env.SHOPIFY_SCOPES || 'read_products';

function cfg() {
    const key = process.env.SHOPIFY_API_KEY;
    const secret = process.env.SHOPIFY_API_SECRET;
    const appUrl = process.env.SHOPIFY_APP_URL;
    if (!key || !secret || !appUrl) {
        throw new Error('Shopify app not configured: set SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_APP_URL');
    }
    return { key, secret, appUrl: appUrl.replace(/\/$/, '') };
}

export function isShopifyConfigured(): boolean {
    return !!(process.env.SHOPIFY_API_KEY && process.env.SHOPIFY_API_SECRET && process.env.SHOPIFY_APP_URL);
}

// ---------------------------------------------------------------------------
// Validation & signature helpers (exported for unit testing)
// ---------------------------------------------------------------------------

export function isValidShopDomain(shop: unknown): shop is string {
    return typeof shop === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/.test(shop);
}

function timingSafeEqualHex(a: string, b: string): boolean {
    const ba = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

/** Verify the HMAC on an OAuth redirect / admin request query. */
export function verifyOAuthHmac(query: Record<string, unknown>, secret: string): boolean {
    const hmac = query.hmac;
    if (typeof hmac !== 'string') return false;
    const message = Object.keys(query)
        .filter((k) => k !== 'hmac' && k !== 'signature')
        .sort()
        .map((k) => {
            const v = query[k];
            return `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`;
        })
        .join('&');
    const digest = crypto.createHmac('sha256', secret).update(message).digest('hex');
    return timingSafeEqualHex(digest, hmac);
}

/** Verify a webhook body against the X-Shopify-Hmac-Sha256 header (base64). */
export function verifyWebhookHmac(rawBody: Buffer, headerHmac: string | undefined, secret: string): boolean {
    if (!headerHmac) return false;
    const digest = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
    return timingSafeEqualHex(digest, headerHmac);
}

/** Verify an App Proxy request signature (hex, params concatenated w/o separators). */
export function verifyAppProxySignature(query: Record<string, unknown>, secret: string): boolean {
    const signature = query.signature;
    if (typeof signature !== 'string') return false;
    const message = Object.keys(query)
        .filter((k) => k !== 'signature')
        .sort()
        .map((k) => {
            const v = query[k];
            return `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`;
        })
        .join('');
    const digest = crypto.createHmac('sha256', secret).update(message).digest('hex');
    return timingSafeEqualHex(digest, signature);
}

// ---------------------------------------------------------------------------
// Shopify Admin API helpers
// ---------------------------------------------------------------------------

async function adminApi(
    shop: string,
    token: string,
    method: string,
    path: string,
    body?: unknown
): Promise<{ statusCode: number; json: any }> {
    const bodyStr = body ? JSON.stringify(body) : undefined;
    const { statusCode, body: text } = await httpsRequest({
        url: `https://${shop}/admin/api/${API_VERSION}/${path}`,
        method,
        headers: {
            'X-Shopify-Access-Token': token,
            'Content-Type': 'application/json',
            ...(bodyStr ? { 'Content-Length': String(Buffer.byteLength(bodyStr)) } : {}),
        },
        body: bodyStr,
        timeoutMs: 30_000,
    });
    let json: any = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* leave null */ }
    return { statusCode, json };
}

async function registerWebhooks(shop: string, token: string, appUrl: string): Promise<void> {
    const topics: Array<[string, string]> = [
        ['app/uninstalled', '/shopify/webhooks/app-uninstalled'],
        ['customers/data_request', '/shopify/webhooks/customers-data-request'],
        ['customers/redact', '/shopify/webhooks/customers-redact'],
        ['shop/redact', '/shopify/webhooks/shop-redact'],
    ];
    for (const [topic, path] of topics) {
        try {
            await adminApi(shop, token, 'POST', 'webhooks.json', {
                webhook: { topic, address: `${appUrl}${path}`, format: 'json' },
            });
        } catch (e) {
            console.warn(`[shopify] webhook register failed (${topic}):`, (e as Error).message);
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

export function registerShopifyRoutes(app: Express): void {
    // ── Install: redirect merchant to Shopify's OAuth consent ────────────────
    app.get('/shopify/auth', async (req: Request, res: Response) => {
        try {
            const { key, appUrl } = cfg();
            const shop = req.query.shop;
            if (!isValidShopDomain(shop)) {
                return res.status(400).send('Invalid or missing ?shop=my-store.myshopify.com');
            }
            const nonce = crypto.randomBytes(16).toString('hex');
            await saveNonce(shop, nonce);
            const redirectUri = `${appUrl}/shopify/auth/callback`;
            const installUrl =
                `https://${shop}/admin/oauth/authorize?client_id=${encodeURIComponent(key)}` +
                `&scope=${encodeURIComponent(SCOPES)}` +
                `&redirect_uri=${encodeURIComponent(redirectUri)}` +
                `&state=${nonce}`;
            res.redirect(installUrl);
        } catch (e) {
            res.status(500).send((e as Error).message);
        }
    });

    // ── OAuth callback: verify, exchange token, provision, register webhooks ──
    app.get('/shopify/auth/callback', async (req: Request, res: Response) => {
        try {
            const { key, secret, appUrl } = cfg();
            const query = req.query as Record<string, unknown>;
            const shop = query.shop;
            const code = query.code;
            const state = query.state;

            if (!isValidShopDomain(shop)) return res.status(400).send('Invalid shop');
            if (!verifyOAuthHmac(query, secret)) return res.status(401).send('HMAC validation failed');
            if (typeof state !== 'string' || !(await consumeNonce(shop, state))) {
                return res.status(403).send('Invalid OAuth state (possible CSRF)');
            }
            if (typeof code !== 'string') return res.status(400).send('Missing code');

            // Exchange the authorization code for an offline access token.
            const tokenBody = JSON.stringify({ client_id: key, client_secret: secret, code });
            const { statusCode, body: tokenText } = await httpsRequest({
                url: `https://${shop}/admin/oauth/access_token`,
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(tokenBody)) },
                body: tokenBody,
                timeoutMs: 30_000,
            });
            if (statusCode < 200 || statusCode >= 300) {
                return res.status(502).send('Token exchange failed');
            }
            const tokenJson = JSON.parse(tokenText) as { access_token: string; scope: string };

            // Auto-provision a plugin site (API key) for this shop, once.
            const existing = await getShopByDomain(shop);
            let pluginSiteId = existing?.plugin_site_id ?? null;
            if (!pluginSiteId) {
                const site = await createPluginSite(`Shopify: ${shop}`, 'shopify', shop);
                pluginSiteId = site.id;
            }

            await upsertShop(shop, tokenJson.access_token, tokenJson.scope ?? SCOPES, pluginSiteId);
            await registerWebhooks(shop, tokenJson.access_token, appUrl);

            // If billing is required, send them to the subscription approval.
            if (/^(1|true|yes|on)$/i.test((process.env.SHOPIFY_BILLING_ENABLED || '').trim())) {
                return res.redirect(`${appUrl}/shopify/billing?shop=${encodeURIComponent(shop)}`);
            }
            // Otherwise land back in the embedded app.
            return res.redirect(`https://${shop}/admin/apps/${key}`);
        } catch (e) {
            res.status(500).send((e as Error).message);
        }
    });

    // ── Billing: create a recurring subscription and redirect to approval ─────
    app.get('/shopify/billing', async (req: Request, res: Response) => {
        try {
            const { key, appUrl } = cfg();
            const shop = req.query.shop;
            if (!isValidShopDomain(shop)) return res.status(400).send('Invalid shop');
            const record = await getShopByDomain(shop);
            if (!record) return res.status(404).send('Shop not installed');

            const planName = process.env.SHOPIFY_PLAN_NAME || 'ZAHA Virtual Try-On';
            const price = process.env.SHOPIFY_PLAN_PRICE || '19.00';
            const trialDays = Number(process.env.SHOPIFY_PLAN_TRIAL_DAYS || 7);
            const test = /^(1|true|yes|on)$/i.test((process.env.SHOPIFY_BILLING_TEST || '').trim());

            const { json } = await adminApi(shop, record.access_token, 'POST', 'recurring_application_charges.json', {
                recurring_application_charge: {
                    name: planName,
                    price,
                    return_url: `${appUrl}/shopify/billing/callback?shop=${encodeURIComponent(shop)}`,
                    trial_days: trialDays,
                    test: test || undefined,
                },
            });
            const charge = json?.recurring_application_charge;
            if (!charge?.confirmation_url) return res.status(502).send('Could not create charge');
            await setShopBilling(shop, planName, String(charge.id), 'pending');
            res.redirect(charge.confirmation_url);
        } catch (e) {
            res.status(500).send((e as Error).message);
        }
    });

    // ── Billing callback: activate the charge the merchant approved ───────────
    app.get('/shopify/billing/callback', async (req: Request, res: Response) => {
        try {
            const { key, appUrl } = cfg();
            const shop = req.query.shop;
            const chargeId = req.query.charge_id;
            if (!isValidShopDomain(shop)) return res.status(400).send('Invalid shop');
            const record = await getShopByDomain(shop);
            if (!record) return res.status(404).send('Shop not installed');

            const { json } = await adminApi(
                shop,
                record.access_token,
                'GET',
                `recurring_application_charges/${encodeURIComponent(String(chargeId))}.json`
            );
            const charge = json?.recurring_application_charge;
            if (!charge) return res.status(404).send('Charge not found');

            if (charge.status === 'accepted') {
                await adminApi(
                    shop,
                    record.access_token,
                    'POST',
                    `recurring_application_charges/${charge.id}/activate.json`,
                    { recurring_application_charge: charge }
                );
                await setShopBilling(shop, record.plan, String(charge.id), 'active');
            } else if (charge.status === 'active') {
                await setShopBilling(shop, record.plan, String(charge.id), 'active');
            } else {
                await setShopBilling(shop, record.plan, String(charge.id), 'cancelled');
            }
            res.redirect(`https://${shop}/admin/apps/${key}`);
        } catch (e) {
            res.status(500).send((e as Error).message);
        }
    });

    // ── App Proxy: theme block fetches its config (no pasted API key) ─────────
    // Configure the proxy in the Partner Dashboard to forward to
    //   {SHOPIFY_APP_URL}/shopify/proxy
    app.get('/shopify/proxy/config', async (req: Request, res: Response) => {
        try {
            const { secret } = cfg();
            const query = req.query as Record<string, unknown>;
            if (!verifyAppProxySignature(query, secret)) {
                return res.status(401).json({ error: 'Invalid signature' });
            }
            const shop = query.shop;
            if (!isValidShopDomain(shop)) return res.status(400).json({ error: 'Invalid shop' });
            const apiKey = await getShopApiKey(shop);
            if (!apiKey) return res.status(404).json({ error: 'Shop not installed' });
            res.json({ apiKey, apiUrl: cfg().appUrl });
        } catch (e) {
            res.status(500).json({ error: (e as Error).message });
        }
    });

    // ── Mandatory webhooks (HMAC-verified via req.rawBody) ────────────────────
    const webhook = (handler: (shop: string, body: any) => Promise<void> | void) =>
        async (req: Request, res: Response) => {
            try {
                const { secret } = cfg();
                const raw = (req as unknown as { rawBody?: Buffer }).rawBody;
                const hmac = req.get('X-Shopify-Hmac-Sha256') || undefined;
                if (!raw || !verifyWebhookHmac(raw, hmac, secret)) {
                    return res.status(401).send('Invalid webhook HMAC');
                }
                const shop = req.get('X-Shopify-Shop-Domain') || '';
                let body: any = {};
                try { body = JSON.parse(raw.toString('utf8')); } catch { /* ignore */ }
                await handler(shop, body);
                res.status(200).send('ok');
            } catch (e) {
                console.error('[shopify] webhook error:', (e as Error).message);
                res.status(500).send('error');
            }
        };

    app.post('/shopify/webhooks/app-uninstalled', webhook(async (shop) => {
        if (shop) await markShopUninstalled(shop);
        console.log(`[shopify] app uninstalled: ${shop}`);
    }));

    // GDPR mandatory topics. ZAHA does not retain customer PII beyond optional
    // emails on plugin sessions; we log and acknowledge. Extend here if you add
    // customer-linked data.
    app.post('/shopify/webhooks/customers-data-request', webhook((shop) => {
        console.log(`[shopify][gdpr] customers/data_request for ${shop}`);
    }));
    app.post('/shopify/webhooks/customers-redact', webhook((shop) => {
        console.log(`[shopify][gdpr] customers/redact for ${shop}`);
    }));
    app.post('/shopify/webhooks/shop-redact', webhook(async (shop) => {
        if (shop) await markShopUninstalled(shop);
        console.log(`[shopify][gdpr] shop/redact for ${shop}`);
    }));
}

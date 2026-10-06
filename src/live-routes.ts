// Live (real-time camera) try-on — powered by Decart's Lucy VTON realtime model.
//
// The browser streams the camera straight to Decart over WebRTC; this server never
// touches the video. Its only jobs are:
//   1. keep the permanent DECART_API_KEY private and hand out short-lived client tokens
//   2. cap what each token can cost (session length, model, sessions per hour)
//   3. fetch garment images from store CDNs on the browser's behalf (CORS)
import { Express, Request, Response, NextFunction } from 'express';
import dns from 'dns';
import http from 'http';
import https from 'https';
import net from 'net';

// ============================================================================
// Configuration
// ============================================================================

function intFromEnv(name: string, fallback: number, min: number, max: number): number {
    const raw = parseInt(process.env[name] || '', 10);
    if (Number.isNaN(raw)) return fallback;
    return Math.max(min, Math.min(max, raw));
}

export interface LiveConfig {
    apiKey: string | null;
    apiBase: string;
    model: string;
    /** Hard cap enforced by Decart on every session minted here. */
    maxSessionSeconds: number;
    /** Sessions one logged-in user may start per rolling hour. */
    sessionsPerHour: number;
    /** Fast mode: lower latency, billed at 2x. */
    fast: boolean;
    allowedOrigins: string[];
}

export function loadLiveConfig(): LiveConfig {
    return {
        apiKey: process.env.DECART_API_KEY?.trim() || null,
        apiBase: (process.env.DECART_API_BASE?.trim() || 'https://api.decart.ai').replace(
            /\/$/,
            ''
        ),
        model: process.env.LIVE_TRYON_MODEL?.trim() || 'lucy-vton-latest',
        maxSessionSeconds: intFromEnv('LIVE_MAX_SESSION_SECONDS', 120, 15, 900),
        sessionsPerHour: intFromEnv('LIVE_SESSIONS_PER_HOUR', 6, 1, 1000),
        fast: process.env.LIVE_FAST_MODE === 'true',
        allowedOrigins: (process.env.LIVE_ALLOWED_ORIGINS || '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
    };
}

/**
 * Seconds the client token itself stays valid. It only has to survive the connect handshake;
 * keeping it short stops a token from being reused to open a second session after the first ends.
 */
const CLIENT_TOKEN_TTL_SECONDS = 60;
const GARMENT_MAX_BYTES = 12 * 1024 * 1024;
const GARMENT_TIMEOUT_MS = 15_000;
const GARMENT_MAX_REDIRECTS = 3;

// ============================================================================
// Per-user session rate limit (in-memory; one process — see ecosystem.config.cjs)
// ============================================================================

const HOUR_MS = 60 * 60 * 1000;
const sessionStarts = new Map<number, number[]>();

/** Returns seconds until the next slot frees up, or 0 if the user may start now. */
export function checkSessionRateLimit(userId: number, limit: number, now = Date.now()): number {
    const recent = (sessionStarts.get(userId) || []).filter((t) => now - t < HOUR_MS);
    sessionStarts.set(userId, recent);
    if (recent.length < limit) return 0;
    return Math.ceil((recent[0] + HOUR_MS - now) / 1000);
}

function recordSessionStart(userId: number, now = Date.now()): void {
    const recent = sessionStarts.get(userId) || [];
    recent.push(now);
    sessionStarts.set(userId, recent);
}

// ============================================================================
// Decart: mint a short-lived client token
// ============================================================================

interface DecartTokenResponse {
    apiKey: string;
    expiresAt: string;
}

function postJson(
    url: string,
    headers: Record<string, string>,
    payload: unknown,
    timeoutMs: number
): Promise<{ statusCode: number; body: string }> {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;
        const body = JSON.stringify(payload);
        const req = lib.request(
            {
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                path: parsed.pathname + parsed.search,
                method: 'POST',
                headers: {
                    ...headers,
                    'Content-Type': 'application/json',
                    'Content-Length': String(Buffer.byteLength(body)),
                },
            },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (ch) => chunks.push(ch));
                res.on('end', () =>
                    resolve({
                        statusCode: res.statusCode || 0,
                        body: Buffer.concat(chunks).toString('utf8'),
                    })
                );
            }
        );
        req.on('error', reject);
        req.setTimeout(timeoutMs, () => {
            req.destroy();
            reject(new Error('Decart request timed out'));
        });
        req.write(body);
        req.end();
    });
}

export async function createDecartClientToken(
    config: LiveConfig,
    userId: number
): Promise<DecartTokenResponse> {
    if (!config.apiKey) throw new Error('DECART_API_KEY is not configured');

    const payload: Record<string, unknown> = {
        expiresIn: CLIENT_TOKEN_TTL_SECONDS,
        allowedModels: [config.model],
        constraints: { realtime: { maxSessionDuration: config.maxSessionSeconds } },
        metadata: { zahaUserId: String(userId) },
    };
    if (config.allowedOrigins.length > 0) payload.allowedOrigins = config.allowedOrigins;

    const { statusCode, body } = await postJson(
        `${config.apiBase}/v1/client/tokens`,
        { 'X-API-KEY': config.apiKey, 'User-Agent': 'zaha-ai-live-try-on' },
        payload,
        20_000
    );

    if (statusCode < 200 || statusCode >= 300) {
        throw new Error(`Decart token request failed (HTTP ${statusCode}): ${body.slice(0, 300)}`);
    }
    const json = JSON.parse(body) as Partial<DecartTokenResponse>;
    if (!json.apiKey) throw new Error('Decart token response did not include a client key');
    return { apiKey: json.apiKey, expiresAt: json.expiresAt || '' };
}

// ============================================================================
// Garment image proxy (guards against requests into private networks)
// ============================================================================

export function isPrivateAddress(ip: string): boolean {
    if (net.isIPv4(ip)) {
        const [a, b] = ip.split('.').map(Number);
        return (
            a === 0 ||
            a === 10 ||
            a === 127 ||
            (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168) ||
            a >= 224
        );
    }
    const v = ip.toLowerCase();
    if (v.startsWith('::ffff:')) {
        const mapped = v.slice(7);
        // Hex-form mapped addresses (::ffff:7f00:1) are refused rather than decoded.
        return net.isIPv4(mapped) ? isPrivateAddress(mapped) : true;
    }
    if (v === '::' || v === '::1') return true;
    return /^(fc|fd|fe[89ab]|ff)/.test(v);
}

type LookupCallback = (
    err: NodeJS.ErrnoException | null,
    address: string | dns.LookupAddress[],
    family?: number
) => void;

/** DNS lookup that refuses hostnames resolving to any private address (covers redirects and rebinding). */
function publicOnlyLookup(
    hostname: string,
    options: dns.LookupOptions,
    callback: LookupCallback
): void {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
        if (err) return callback(err, []);
        const list = addresses as dns.LookupAddress[];
        if (list.length === 0 || list.some((a) => isPrivateAddress(a.address))) {
            const blocked: NodeJS.ErrnoException = new Error('Address is not publicly reachable');
            blocked.code = 'EBLOCKED';
            return callback(blocked, []);
        }
        if (options.all) return callback(null, list);
        callback(null, list[0].address, list[0].family);
    });
}

export interface RemoteImage {
    contentType: string;
    data: Buffer;
}

export function fetchRemoteImage(
    rawUrl: string,
    opts: { allowPrivate?: boolean; redirectsLeft?: number } = {}
): Promise<RemoteImage> {
    const redirectsLeft = opts.redirectsLeft ?? GARMENT_MAX_REDIRECTS;
    return new Promise((resolve, reject) => {
        let parsed: URL;
        try {
            const s = rawUrl.trim();
            parsed = new URL(s.startsWith('//') ? 'https:' + s : s);
        } catch {
            return reject(new Error('Invalid image URL'));
        }
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return reject(new Error('Image URL must use http or https'));
        }
        // IP literals skip DNS, so the lookup guard never sees them.
        const host = parsed.hostname.replace(/^\[|\]$/g, '');
        if (!opts.allowPrivate && net.isIP(host) && isPrivateAddress(host)) {
            return reject(new Error('Address is not publicly reachable'));
        }

        const lib = parsed.protocol === 'https:' ? https : http;
        const req = lib.get(
            parsed,
            {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; ZahaTryOn/1.0)',
                    Accept: 'image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8',
                },
                ...(opts.allowPrivate
                    ? {}
                    : { lookup: publicOnlyLookup as unknown as net.LookupFunction }),
            },
            (res) => {
                const status = res.statusCode || 0;
                if (status >= 300 && status < 400 && res.headers.location) {
                    res.resume();
                    if (redirectsLeft <= 0) return reject(new Error('Too many redirects'));
                    const next = new URL(res.headers.location, parsed).href;
                    return fetchRemoteImage(next, {
                        ...opts,
                        redirectsLeft: redirectsLeft - 1,
                    }).then(resolve, reject);
                }
                if (status < 200 || status >= 300) {
                    res.resume();
                    return reject(new Error(`Image host returned HTTP ${status}`));
                }
                const contentType = String(res.headers['content-type'] || '')
                    .split(';')[0]
                    .trim()
                    .toLowerCase();
                const isImage = contentType.startsWith('image/') && contentType !== 'image/svg+xml';
                if (!isImage && contentType !== 'application/octet-stream') {
                    res.resume();
                    return reject(new Error('That URL is not an image'));
                }
                const declared = parseInt(String(res.headers['content-length'] || '0'), 10);
                if (declared > GARMENT_MAX_BYTES) {
                    res.destroy();
                    return reject(new Error('Image is too large (max 12MB)'));
                }
                const chunks: Buffer[] = [];
                let total = 0;
                res.on('data', (ch: Buffer) => {
                    total += ch.length;
                    if (total > GARMENT_MAX_BYTES) {
                        res.destroy();
                        return reject(new Error('Image is too large (max 12MB)'));
                    }
                    chunks.push(ch);
                });
                res.on('end', () => resolve({ contentType, data: Buffer.concat(chunks) }));
                res.on('error', reject);
            }
        );
        req.on('error', (e: NodeJS.ErrnoException) =>
            reject(e.code === 'EBLOCKED' ? new Error('Address is not publicly reachable') : e)
        );
        req.setTimeout(GARMENT_TIMEOUT_MS, () => {
            req.destroy();
            reject(new Error('Image download timed out'));
        });
    });
}

// ============================================================================
// Routes
// ============================================================================

interface LiveRouteDeps {
    requireAuth: (req: Request, res: Response, next: NextFunction) => void;
}

export function registerLiveRoutes(app: Express, deps: LiveRouteDeps): LiveConfig {
    const { requireAuth } = deps;
    const config = loadLiveConfig();

    // Public: lets the page explain itself before asking anyone to log in.
    app.get('/api/live/config', (_req: Request, res: Response) => {
        res.json({
            enabled: !!config.apiKey,
            model: config.model,
            maxSessionSeconds: config.maxSessionSeconds,
            sessionsPerHour: config.sessionsPerHour,
            fast: config.fast,
        });
    });

    // Mint a single-session client token. This is the call that authorises spend.
    app.post('/api/live/token', requireAuth, async (req: Request, res: Response) => {
        if (!config.apiKey) {
            return res.status(503).json({ error: 'Live try-on is not configured on this server.' });
        }
        const user = req.user!;
        if (user.role !== 'superadmin') {
            const retryAfter = checkSessionRateLimit(user.id, config.sessionsPerHour);
            if (retryAfter > 0) {
                res.set('Retry-After', String(retryAfter));
                return res.status(429).json({
                    error: `You've reached the limit of ${config.sessionsPerHour} live sessions per hour. Try again in ${Math.ceil(retryAfter / 60)} min.`,
                    retryAfterSeconds: retryAfter,
                });
            }
        }
        try {
            const token = await createDecartClientToken(config, user.id);
            recordSessionStart(user.id);
            console.log(
                `🎥 Live try-on session authorised: user=${user.id} model=${config.model} cap=${config.maxSessionSeconds}s`
            );
            res.set('Cache-Control', 'no-store');
            res.json({
                apiKey: token.apiKey,
                expiresAt: token.expiresAt,
                model: config.model,
                maxSessionSeconds: config.maxSessionSeconds,
                fast: config.fast,
            });
        } catch (e: unknown) {
            console.error('Live token error:', (e as Error).message);
            res.status(502).json({
                error: 'Could not start a live session. Please try again in a moment.',
            });
        }
    });

    // Fetch a garment image from a store CDN so the browser can read its pixels.
    app.get('/api/live/garment', requireAuth, async (req: Request, res: Response) => {
        const url = typeof req.query.url === 'string' ? req.query.url : '';
        if (!url) return res.status(400).json({ error: 'url is required' });
        try {
            const image = await fetchRemoteImage(url);
            res.set('Content-Type', image.contentType);
            res.set('Cache-Control', 'private, max-age=300');
            // Third-party bytes served from our origin: never let a browser render them as a document.
            res.set('X-Content-Type-Options', 'nosniff');
            res.set('Content-Security-Policy', "default-src 'none'; sandbox");
            res.set('Content-Disposition', 'attachment; filename="garment"');
            res.send(image.data);
        } catch (e: unknown) {
            res.status(400).json({ error: (e as Error).message || 'Could not load that image' });
        }
    });

    return config;
}

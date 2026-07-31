// ============================================================================
// Minimal Replicate API client (shared by the fidelity + enhancement stages).
// No SDK dependency — plain HTTPS so it works in the same IPv4-only style as
// the rest of the app. All calls are optional: if REPLICATE_API_TOKEN is not
// set, isReplicateConfigured() returns false and callers skip their stage.
// ============================================================================

import https from 'https';

export function isReplicateConfigured(): boolean {
    return !!(process.env.REPLICATE_API_TOKEN && process.env.REPLICATE_API_TOKEN.trim());
}

function token(): string {
    const t = process.env.REPLICATE_API_TOKEN;
    if (!t) throw new Error('REPLICATE_API_TOKEN not set');
    return t.trim();
}

function apiRequest(method: string, path: string, body?: unknown): Promise<any> {
    const payload = body ? JSON.stringify(body) : undefined;
    return new Promise((resolve, reject) => {
        const req = https.request(
            {
                hostname: 'api.replicate.com',
                path,
                method,
                headers: {
                    Authorization: `Bearer ${token()}`,
                    'Content-Type': 'application/json',
                    ...(payload ? { 'Content-Length': String(Buffer.byteLength(payload)) } : {}),
                },
            },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c) => chunks.push(c));
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
                    } catch (e) {
                        reject(e);
                    }
                });
            }
        );
        req.on('error', reject);
        req.setTimeout(30_000, () => { req.destroy(); reject(new Error('Replicate request timeout')); });
        if (payload) req.write(payload);
        req.end();
    });
}

function getUrl(url: string): Promise<any> {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const req = https.request(
            { hostname: u.hostname, path: u.pathname + u.search, method: 'GET', headers: { Authorization: `Bearer ${token()}` } },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c) => chunks.push(c));
                res.on('end', () => {
                    try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
                    catch (e) { reject(e); }
                });
            }
        );
        req.on('error', reject);
        req.setTimeout(30_000, () => { req.destroy(); reject(new Error('Replicate poll timeout')); });
        req.end();
    });
}

export function downloadBuffer(url: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            if (res.statusCode && res.statusCode >= 400) {
                reject(new Error(`Download failed (HTTP ${res.statusCode})`));
                return;
            }
            const chunks: Buffer[] = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks)));
        }).on('error', reject);
    });
}

/** Turn a raw image buffer into a data: URI Replicate accepts as input. */
export function toDataUri(buffer: Buffer, mime = 'image/png'): string {
    return `data:${mime};base64,${buffer.toString('base64')}`;
}

/**
 * Run a Replicate model version to completion and return its output.
 * Output is model-specific: often a single URL string or an array of URLs.
 */
export async function runReplicate(
    version: string,
    input: Record<string, unknown>,
    opts: { maxAttempts?: number; intervalMs?: number } = {}
): Promise<string | string[]> {
    const maxAttempts = opts.maxAttempts ?? 90; // ~3 min at 2s
    const intervalMs = opts.intervalMs ?? 2000;

    const prediction = await apiRequest('POST', '/v1/predictions', { version, input });
    let status = prediction.status as string;
    let output = prediction.output as string | string[] | undefined;
    const pollUrl = prediction?.urls?.get as string | undefined;

    let attempts = 0;
    while ((status === 'starting' || status === 'processing') && pollUrl && attempts < maxAttempts) {
        await new Promise((r) => setTimeout(r, intervalMs));
        const poll = await getUrl(pollUrl);
        status = poll.status;
        output = poll.output;
        attempts++;
    }

    if (status !== 'succeeded' || output == null) {
        throw new Error(`Replicate model did not succeed (status=${status})`);
    }
    return output;
}

import crypto from 'crypto';
import https from 'https';

const GCP_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';

let cachedToken: { token: string; expiresAt: number } | null = null;

/** HTTPS via IPv4 only — avoids EC2 IPv6-unreachable + node-fetch gzip issues with Google APIs. */
export function httpsRequest(options: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
}): Promise<{ statusCode: number; body: string }> {
    return new Promise((resolve, reject) => {
        const parsed = new URL(options.url);
        const req = https.request(
            {
                hostname: parsed.hostname,
                port: parsed.port || 443,
                path: parsed.pathname + parsed.search,
                method: options.method || 'GET',
                family: 4,
                headers: options.headers,
            },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (ch) => chunks.push(ch));
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode || 0,
                        body: Buffer.concat(chunks).toString('utf8'),
                    });
                });
            }
        );
        req.on('error', reject);
        req.setTimeout(options.timeoutMs ?? 120_000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        if (options.body) req.write(options.body);
        req.end();
    });
}

function buildServiceAccountJwt(credentials: Record<string, unknown>, tokenUri: string): string {
    const email = credentials.client_email as string;
    const privateKey = credentials.private_key as string;
    if (!email || !privateKey) {
        throw new Error('Service account credentials missing client_email or private_key');
    }

    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const claim = Buffer.from(
        JSON.stringify({
            iss: email,
            scope: GCP_SCOPE,
            aud: tokenUri,
            iat: now,
            exp: now + 3600,
        })
    ).toString('base64url');
    const signInput = `${header}.${claim}`;
    const sign = crypto.createSign('RSA-SHA256').update(signInput).sign(privateKey, 'base64url');
    return `${signInput}.${sign}`;
}

/** Exchange service account JWT for access token using native HTTPS (not google-auth-library fetch). */
export async function getServiceAccountAccessToken(
    credentials: Record<string, unknown>,
    forceRefresh = false
): Promise<string> {
    if (!forceRefresh && cachedToken && cachedToken.expiresAt > Date.now() + 60_000) {
        return cachedToken.token;
    }

    const tokenUri = (credentials.token_uri as string) || 'https://oauth2.googleapis.com/token';
    const postBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: buildServiceAccountJwt(credentials, tokenUri),
    }).toString();

    const { statusCode, body } = await httpsRequest({
        url: tokenUri,
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': String(Buffer.byteLength(postBody)),
        },
        body: postBody,
        timeoutMs: 30_000,
    });

    if (statusCode < 200 || statusCode >= 300) {
        let errMsg = body;
        try {
            const j = JSON.parse(body) as { error?: string; error_description?: string };
            errMsg = j.error_description || j.error || body;
        } catch {
            /* use raw body */
        }
        throw new Error(`Google token error (HTTP ${statusCode}): ${errMsg}`);
    }

    const json = JSON.parse(body) as { access_token?: string; expires_in?: number };
    if (!json.access_token) {
        throw new Error('Google token response missing access_token');
    }

    cachedToken = {
        token: json.access_token,
        expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000,
    };
    return json.access_token;
}

export async function getServiceAccountAccessTokenWithRetry(
    credentials: Record<string, unknown>,
    maxAttempts = 4
): Promise<string> {
    let lastError: Error | undefined;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            return await getServiceAccountAccessToken(credentials, attempt > 1);
        } catch (e: unknown) {
            lastError = e as Error;
            if (attempt === maxAttempts) break;
            await new Promise((r) => setTimeout(r, 1000 * attempt));
        }
    }
    throw lastError ?? new Error('Failed to obtain Google access token');
}

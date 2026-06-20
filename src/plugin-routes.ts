import { Express, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import https from 'https';
import http from 'http';
import * as cheerio from 'cheerio';
import {
    getPluginSiteByApiKey,
    getPluginSessionByToken,
    getPromoByCode,
    redeemPromoForPlugin,
    deductPluginCredit,
    insertPluginTryOnHistory,
    listPromoCodes,
    createPromoCode,
    updatePromoCode,
    deletePromoCode,
    listPluginSites,
    createPluginSite,
    PluginSite,
    PluginSession,
} from './plugin-db';
import { downloadAndPrepareProductImage, preferJpegProductUrl } from './image-utils';

declare global {
    namespace Express {
        interface Request {
            pluginSite?: PluginSite;
            pluginSession?: PluginSession;
        }
    }
}

type TryOnGenerator = (
    personPath: string,
    productPath: string,
    sampleCount: number
) => Promise<Array<{ mimeType: string; bytesBase64Encoded: string }>>;

interface PluginRouteDeps {
    upload: multer.Multer;
    paths: { uploads: string; outputs: string };
    generateTryOn: TryOnGenerator;
    requireSuperadmin: (req: Request, res: Response, next: NextFunction) => void;
    downloadImageToFile: (url: string, dest: string) => Promise<void>;
}

function getApiKey(req: Request): string | null {
    const h = req.get('X-Zaha-Api-Key') || req.get('Authorization');
    if (!h) return null;
    if (h.startsWith('Bearer ')) return h.slice(7).trim();
    return h.trim();
}

function getSessionToken(req: Request): string | null {
    return req.get('X-Zaha-Session')?.trim() || (req.body as { sessionToken?: string })?.sessionToken || null;
}

async function requirePluginKey(req: Request, res: Response, next: NextFunction): Promise<void> {
    const key = getApiKey(req);
    if (!key) {
        res.status(401).json({ error: 'Missing X-Zaha-Api-Key header' });
        return;
    }
    const site = await getPluginSiteByApiKey(key);
    if (!site) {
        res.status(401).json({ error: 'Invalid API key' });
        return;
    }
    req.pluginSite = site;
    next();
}

async function requirePluginSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    const token = getSessionToken(req);
    if (!token) {
        res.status(401).json({ error: 'Missing session. Redeem a promo code first.' });
        return;
    }
    const sess = await getPluginSessionByToken(token);
    if (!sess) {
        res.status(401).json({ error: 'Session expired or invalid. Redeem a promo code again.' });
        return;
    }
    if (req.pluginSite && sess.site_id !== req.pluginSite.id) {
        res.status(403).json({ error: 'Session does not belong to this site' });
        return;
    }
    req.pluginSession = sess;
    next();
}

async function extractProductImageUrl(url: string): Promise<string> {
    const parsed = new URL(url);
    const headers: Record<string, string> = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        Referer: parsed.origin + '/',
    };
    const html = await new Promise<string>((resolve, reject) => {
        const lib = parsed.protocol === 'https:' ? https : http;
        const req2 = lib.get(url, { headers }, (r) => {
            let data = '';
            r.on('data', (ch) => { data += ch; });
            r.on('end', () => resolve(data));
        });
        req2.on('error', reject);
        req2.setTimeout(15000, () => { req2.destroy(); reject(new Error('Request timeout')); });
    });
    const $ = cheerio.load(html);
    const normalizeUrl = (src: string): string =>
        src.startsWith('//') ? 'https:' + src : src.startsWith('/') ? parsed.origin + src : src;

    const ogImage = $('meta[property="og:image"]').attr('content');
    if (ogImage && ogImage.length > 10) return normalizeUrl(ogImage);

    let productImageUrl: string | null = null;
    $('script[type="application/ld+json"]').each((_, el) => {
        if (productImageUrl) return false;
        try {
            const json = JSON.parse($(el).html() || '{}');
            const item = json['@graph']?.[0] || json;
            const img = item.image || item.thumbnailUrl;
            if (typeof img === 'string' && img.length > 10) {
                productImageUrl = normalizeUrl(img);
                return false;
            }
            if (Array.isArray(img) && img[0]) {
                productImageUrl = normalizeUrl(String(img[0]));
                return false;
            }
        } catch { /* ignore */ }
    });
    if (productImageUrl) return productImageUrl;

    const img = $('img[src*="product"], .product-image img, [data-product-image]').first().attr('src');
    if (img) return normalizeUrl(img);

    throw new Error('Could not find product image on this page');
}

export function registerPluginRoutes(app: Express, deps: PluginRouteDeps): void {
    const { upload, paths, generateTryOn, requireSuperadmin, downloadImageToFile } = deps;

    // ── Plugin: redeem promo ──────────────────────────────────────────────
    app.post('/api/plugin/redeem-promo', requirePluginKey, async (req: Request, res: Response) => {
        try {
            const { code, email } = req.body as { code?: string; email?: string };
            if (!code) return res.status(400).json({ error: 'Promo code required' });
            const promo = await getPromoByCode(code);
            if (!promo) return res.status(404).json({ error: 'Invalid or inactive promo code' });
            const session = await redeemPromoForPlugin(req.pluginSite!.id, promo, email);
            res.json({
                ok: true,
                sessionToken: session.token,
                creditsRemaining: session.credits_remaining,
                promoCode: promo.code,
            });
        } catch (e: unknown) {
            res.status(400).json({ error: (e as Error).message || 'Redemption failed' });
        }
    });

    // ── Plugin: check credits ─────────────────────────────────────────────
    app.get('/api/plugin/credits', requirePluginKey, requirePluginSession, (req: Request, res: Response) => {
        res.json({ creditsRemaining: req.pluginSession!.credits_remaining });
    });

    // ── Plugin: extract product from URL ──────────────────────────────────
    app.post('/api/plugin/extract-product', requirePluginKey, async (req: Request, res: Response) => {
        try {
            const { url } = req.body as { url?: string };
            if (!url) return res.status(400).json({ error: 'URL required' });
            const productImageUrl = await extractProductImageUrl(url);
            res.json({ productImageUrl: preferJpegProductUrl(productImageUrl) });
        } catch (e: unknown) {
            res.status(400).json({ error: (e as Error).message || 'Extraction failed' });
        }
    });

    // ── Plugin: virtual try-on (uses credits) ─────────────────────────────
    app.post(
        '/api/plugin/try-on',
        requirePluginKey,
        requirePluginSession,
        upload.fields([
            { name: 'personImage', maxCount: 1 },
            { name: 'productImage', maxCount: 1 },
        ]),
        async (req: Request, res: Response) => {
            try {
                if (req.pluginSession!.credits_remaining <= 0) {
                    return res.status(402).json({ error: 'No try-on credits remaining. Redeem a promo code.' });
                }

                const files = (req.files || {}) as { [fieldname: string]: Express.Multer.File[] };
                const body = req.body as { productImageUrl?: string; sampleCount?: string };
                const generationId = Date.now();

                if (!files.personImage?.[0]) {
                    return res.status(400).json({ error: 'Person image is required' });
                }

                const personImage = files.personImage[0];
                const personExt = path.extname(personImage.filename);
                const personNewFilename = `person-${generationId}${personExt}`;
                const personNewPath = path.join(paths.uploads, personNewFilename);
                fs.renameSync(personImage.path, personNewPath);

                let productNewPath: string;
                let productNewFilename: string;

                if (files.productImage?.[0]) {
                    const productImage = files.productImage[0];
                    const productExt = path.extname(productImage.filename);
                    productNewFilename = `product-${generationId}${productExt}`;
                    productNewPath = path.join(paths.uploads, productNewFilename);
                    fs.renameSync(productImage.path, productNewPath);
                } else if (body.productImageUrl) {
                    productNewFilename = `product-${generationId}.jpg`;
                    productNewPath = path.join(paths.uploads, productNewFilename);
                    await downloadAndPrepareProductImage(body.productImageUrl, paths.uploads, generationId, downloadImageToFile);
                } else {
                    return res.status(400).json({ error: 'Product image (file or URL) is required' });
                }

                const sampleCount = Math.max(1, Math.min(4, parseInt(body.sampleCount || '1', 10)));
                const predictions = await generateTryOn(personNewPath, productNewPath, sampleCount);

                const savedImages: string[] = [];
                for (const prediction of predictions) {
                    const ext = prediction.mimeType.split('/')[1] || 'png';
                    const outputFilename = `result-${generationId}.${ext}`;
                    const outputPath = path.join(paths.outputs, outputFilename);
                    fs.writeFileSync(outputPath, Buffer.from(prediction.bytesBase64Encoded, 'base64'));
                    savedImages.push(`/outputs/${outputFilename}`);
                }

                const creditsRemaining = await deductPluginCredit(req.pluginSession!.id);
                await insertPluginTryOnHistory(
                    req.pluginSession!.id,
                    generationId,
                    personNewFilename,
                    productNewFilename,
                    savedImages.map((u) => path.basename(u))
                );

                res.json({
                    success: true,
                    id: generationId,
                    resultImages: savedImages,
                    creditsRemaining,
                    count: savedImages.length,
                });
            } catch (e: unknown) {
                console.error('Plugin try-on error:', e);
                res.status(500).json({ error: (e as Error).message || 'Try-on failed' });
            }
        }
    );

    // ── Admin: promo codes ────────────────────────────────────────────────
    app.get('/api/admin/promos', requireSuperadmin, async (_req: Request, res: Response) => {
        try {
            res.json({ promos: await listPromoCodes() });
        } catch (e: unknown) {
            res.status(500).json({ error: (e as Error).message });
        }
    });

    app.post('/api/admin/promos', requireSuperadmin, async (req: Request, res: Response) => {
        try {
            const { code, try_on_credits, max_redemptions, expires_at, notes } = req.body as {
                code?: string;
                try_on_credits?: number;
                max_redemptions?: number;
                expires_at?: string;
                notes?: string;
            };
            if (!code) return res.status(400).json({ error: 'Code required' });
            const promo = await createPromoCode({
                code,
                try_on_credits: try_on_credits ?? 1,
                max_redemptions: max_redemptions ?? 1,
                expires_at: expires_at ?? null,
                notes: notes ?? null,
            });
            res.json({ promo });
        } catch (e: unknown) {
            res.status(400).json({ error: (e as Error).message });
        }
    });

    app.patch('/api/admin/promos/:id', requireSuperadmin, async (req: Request, res: Response) => {
        try {
            const id = parseInt(req.params.id, 10);
            const promo = await updatePromoCode(id, req.body);
            if (!promo) return res.status(404).json({ error: 'Not found' });
            res.json({ promo });
        } catch (e: unknown) {
            res.status(400).json({ error: (e as Error).message });
        }
    });

    app.delete('/api/admin/promos/:id', requireSuperadmin, async (req: Request, res: Response) => {
        try {
            const id = parseInt(req.params.id, 10);
            await deletePromoCode(id);
            res.json({ ok: true });
        } catch (e: unknown) {
            res.status(500).json({ error: (e as Error).message });
        }
    });

    app.get('/api/admin/plugin-sites', requireSuperadmin, async (_req: Request, res: Response) => {
        try {
            res.json({ sites: await listPluginSites() });
        } catch (e: unknown) {
            res.status(500).json({ error: (e as Error).message });
        }
    });

    app.post('/api/admin/plugin-sites', requireSuperadmin, async (req: Request, res: Response) => {
        try {
            const { name, platform, allowed_domains } = req.body as {
                name?: string;
                platform?: string;
                allowed_domains?: string;
            };
            if (!name) return res.status(400).json({ error: 'Name required' });
            const site = await createPluginSite(name, platform || 'wordpress', allowed_domains);
            res.json({ site });
        } catch (e: unknown) {
            res.status(400).json({ error: (e as Error).message });
        }
    });
}

// Web server for Virtual Try-On interface
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import multer from 'multer';
import cors from 'cors';
import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import https from 'https';
import http from 'http';
import { GoogleAuth } from 'google-auth-library';
import * as cheerio from 'cheerio';
import {
    getUserByEmail,
    getUserById,
    createUser,
    countUsers,
    insertTryOnHistory,
    getTryOnHistoryByUser,
    getTryOnByGenerationId,
    deleteTryOnHistory,
    testConnection,
    type User,
} from './db';

// Load environment variables
dotenv.config();

// ============================================================================
// Types & Interfaces
// ============================================================================

type MulterFile = Express.Multer.File;

interface VirtualTryOnResult {
    id: number;
    personImageUrl: string;
    productImageUrl: string;
    resultImages: string[];
    /** Set when superadmin: creator's email */
    userEmail?: string;
}

declare global {
    namespace Express {
        interface Request {
            user?: User;
        }
    }
}

interface PredictionResponse {
    mimeType: string;
    bytesBase64Encoded: string;
}

interface APIResponse {
    predictions?: Array<{ mimeType?: string; bytesBase64Encoded?: string }>;
}

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
    PROJECT_ID: process.env.PROJECT_ID,
    LOCATION: process.env.LOCATION,
    PORT: Number(process.env.PORT) || 3000,
    MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
    VIRTUAL_TRY_ON_MODEL: 'virtual-try-on-001',
} as const;

const PATHS = {
    SERVICE_ACCOUNT_KEY:
        process.env.GOOGLE_APPLICATION_CREDENTIALS ||
        (process.env.SERVICE_ACCOUNT_KEY_PATH
            ? path.resolve(process.cwd(), process.env.SERVICE_ACCOUNT_KEY_PATH)
            : path.resolve(process.cwd(), 'service-account-key.json')),
    UPLOADS: path.join(process.cwd(), 'uploads'),
    OUTPUTS: path.join(process.cwd(), 'outputs'),
} as const;

const IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp'] as const;

const MIME_TYPES: Record<string, string> = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
};

// ============================================================================
// Utility Functions
// ============================================================================

class FileUtils {
    static ensureDirectoryExists(dirPath: string): void {
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }
    }

    static getMimeType(filePath: string): string {
        const ext = path.extname(filePath).toLowerCase();
        return MIME_TYPES[ext] || 'image/png';
    }

    static imageToBase64(filePath: string): string {
        if (!fs.existsSync(filePath)) {
            throw new Error(`File not found at path: ${filePath}`);
        }
        const fileBuffer = fs.readFileSync(filePath);
        return fileBuffer.toString('base64');
    }

    static isValidImageFile(filename: string, mimeType: string): boolean {
        const ext = path.extname(filename).toLowerCase();
        const isValidExtension = IMAGE_EXTENSIONS.includes(
            ext as (typeof IMAGE_EXTENSIONS)[number]
        );
        const isValidMimeType = mimeType.startsWith('image/');
        return isValidExtension && isValidMimeType;
    }

    static getFilesByPrefix(dirPath: string, prefix: string): string[] {
        if (!fs.existsSync(dirPath)) {
            return [];
        }
        return fs.readdirSync(dirPath).filter((file) => file.startsWith(prefix));
    }

    static extractGenerationId(filename: string, prefix: string): number | null {
        const regex = new RegExp(`^${prefix}-(\\d+)`);
        const match = filename.match(regex);
        return match ? parseInt(match[1], 10) : null;
    }
}

function getGoogleAuthOptions(): { keyFilename?: string; credentials?: object } {
    const jsonKey = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    if (jsonKey && jsonKey.trim()) {
        try {
            const credentials = JSON.parse(jsonKey) as object;
            return { credentials };
        } catch {
            throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is set but is not valid JSON.');
        }
    }
    return { keyFilename: PATHS.SERVICE_ACCOUNT_KEY };
}

class VirtualTryOnService {
    private static getApiEndpoint(): string {
        if (!CONFIG.PROJECT_ID || !CONFIG.LOCATION) {
            throw new Error('PROJECT_ID and LOCATION must be set in environment variables');
        }
        return `https://${CONFIG.LOCATION}-aiplatform.googleapis.com/v1/projects/${CONFIG.PROJECT_ID}/locations/${CONFIG.LOCATION}/publishers/google/models/${CONFIG.VIRTUAL_TRY_ON_MODEL}:predict`;
    }

    private static async getAccessToken(): Promise<string> {
        const auth = new GoogleAuth({
            ...getGoogleAuthOptions(),
            scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        });
        const client = await auth.getClient();
        const accessToken = await client.getAccessToken();

        if (!accessToken.token) {
            throw new Error('Failed to obtain access token');
        }

        return accessToken.token;
    }

    static async generateVirtualTryOn(
        personImagePath: string,
        productImagePath: string,
        sampleCount: number = 1
    ): Promise<PredictionResponse[]> {
        const apiEndpoint = this.getApiEndpoint();
        const accessToken = await this.getAccessToken();

        const personImageBase64 = FileUtils.imageToBase64(personImagePath);
        const productImageBase64 = FileUtils.imageToBase64(productImagePath);

        const requestBody = {
            instances: [
                {
                    personImage: {
                        image: {
                            bytesBase64Encoded: personImageBase64,
                        },
                    },
                    productImages: [
                        {
                            image: {
                                bytesBase64Encoded: productImageBase64,
                            },
                        },
                    ],
                },
            ],
            parameters: {
                sampleCount: Math.max(1, Math.min(4, sampleCount)),
            },
        };

        const response = await fetch(apiEndpoint, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(
                `Virtual Try-On API error: ${response.status} ${response.statusText}. ${errorText}`
            );
        }

        const responseData = (await response.json()) as APIResponse;

        if (!responseData.predictions || responseData.predictions.length === 0) {
            throw new Error('Virtual Try-On API returned no predictions');
        }

        return responseData.predictions.map((pred) => ({
            mimeType: pred.mimeType || 'image/png',
            bytesBase64Encoded: pred.bytesBase64Encoded || '',
        }));
    }
}

class ResultService {
    static getAllResults(): VirtualTryOnResult[] {
        const results: VirtualTryOnResult[] = [];

        const personFiles = FileUtils.getFilesByPrefix(PATHS.UPLOADS, 'person-');
        const productFiles = FileUtils.getFilesByPrefix(PATHS.UPLOADS, 'product-');
        const resultFiles = FileUtils.getFilesByPrefix(PATHS.OUTPUTS, 'result-');

        // Extract generation IDs from person files
        const generationIds = new Set<number>();
        personFiles.forEach((file) => {
            const id = FileUtils.extractGenerationId(file, 'person');
            if (id !== null) {
                generationIds.add(id);
            }
        });

        // Match files by generation ID
        Array.from(generationIds)
            .sort((a, b) => b - a) // Sort descending (newest first)
            .forEach((id) => {
                const personFile = personFiles.find((f) => f.startsWith(`person-${id}`));
                const productFile = productFiles.find((f) => f.startsWith(`product-${id}`));
                const matchingResults = resultFiles
                    .filter((f) => {
                        const resultId = FileUtils.extractGenerationId(f, 'result');
                        return resultId === id;
                    })
                    .sort()
                    .map((f) => `/outputs/${f}`);

                if (personFile && productFile && matchingResults.length > 0) {
                    const personPath = path.join(PATHS.UPLOADS, personFile);
                    const productPath = path.join(PATHS.UPLOADS, productFile);
                    const resultPath = path.join(
                        PATHS.OUTPUTS,
                        matchingResults[0].replace('/outputs/', '')
                    );

                    // Verify all files exist
                    if (
                        fs.existsSync(personPath) &&
                        fs.existsSync(productPath) &&
                        fs.existsSync(resultPath)
                    ) {
                        results.push({
                            id,
                            personImageUrl: `/uploads/${personFile}`,
                            productImageUrl: `/uploads/${productFile}`,
                            resultImages: matchingResults,
                        });
                    }
                }
            });

        return results;
    }
}

// ============================================================================
// Initialization
// ============================================================================

function initializeApp(): void {
    // Setup directories
    FileUtils.ensureDirectoryExists(PATHS.UPLOADS);
    FileUtils.ensureDirectoryExists(PATHS.OUTPUTS);

    // Setup authentication: use env JSON (e.g. Render) or key file (local)
    const jsonKey = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    if (jsonKey && jsonKey.trim()) {
        try {
            JSON.parse(jsonKey);
        } catch {
            throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is set but is not valid JSON.');
        }
        return;
    }
    const keyPath = PATHS.SERVICE_ACCOUNT_KEY;
    if (!keyPath || !fs.existsSync(keyPath)) {
        const msg = [
            'Service account key file not found. Vertex AI requires a Google Cloud service account key.',
            '',
            'Fix by doing ONE of the following:',
            '  1. (Production e.g. Render) Set env var GOOGLE_SERVICE_ACCOUNT_JSON to the full JSON key content.',
            '  2. (Local) Place your key file at: ' + path.resolve(process.cwd(), 'service-account-key.json'),
            '  3. Set SERVICE_ACCOUNT_KEY_PATH in .env, or GOOGLE_APPLICATION_CREDENTIALS to the key file path.',
            '',
            'To create a key: Google Cloud Console → IAM & Admin → Service Accounts → create/select → Keys → Add key → JSON.',
        ].join('\n');
        throw new Error(msg);
    }
    if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
        process.env.GOOGLE_APPLICATION_CREDENTIALS = keyPath;
    }
}

// ============================================================================
// Express App Setup
// ============================================================================

const app = express();

// Required on Render/Heroku etc.: trust the reverse proxy so req.secure and cookies work
app.set('trust proxy', 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Use PostgreSQL session store when DATABASE_URL is set (persists across Render instances/restarts)
const sessionConfig: session.SessionOptions = {
    secret: process.env.SESSION_SECRET || 'zaha-ai-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
        sameSite: 'lax',
    },
};
if (process.env.DATABASE_URL) {
    const PgSession = connectPgSimple(session);
    sessionConfig.store = new PgSession({
        conString: process.env.DATABASE_URL,
        createTableIfMissing: true,
    });
}
app.use(session(sessionConfig));
app.use(
    express.static('public', {
        setHeaders: (res) => {
            if (process.env.NODE_ENV !== 'production') {
                res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
            }
        },
    })
);
app.use('/uploads', express.static(PATHS.UPLOADS));
app.use('/outputs', express.static(PATHS.OUTPUTS));

// Load user from session
app.use(async (req: Request, _res: Response, next: () => void) => {
    const sid = (req.session as unknown as { userId?: number })?.userId;
    if (sid) {
        try {
            req.user = await getUserById(sid) ?? undefined;
        } catch {
            req.user = undefined;
        }
    }
    next();
});

function requireAuth(req: Request, res: Response, next: () => void): void {
    if (!req.user) {
        res.status(401).json({ error: 'Login required' });
        return;
    }
    next();
}

function isDbConnectionError(e: unknown): boolean {
    const err = e as { code?: string; errno?: string };
    return err?.code === 'ECONNREFUSED' || err?.code === 'ETIMEDOUT' || err?.errno === 'ECONNREFUSED';
}

const DB_UNAVAILABLE_MSG =
    'Database is unavailable. If you run the app locally, the database may only be reachable from your hosting provider. Try again after deploying or use a local MySQL.';

// ----------------------------------------------------------------------------
// Auth API
// ----------------------------------------------------------------------------
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/auth/register', async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body as { email?: string; password?: string };
        if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Email and password required' });
        }
        const e = email.trim().toLowerCase();
        if (!EMAIL_REGEX.test(e)) return res.status(400).json({ error: 'Please enter a valid email address' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
        const existing = await getUserByEmail(e);
        if (existing) return res.status(400).json({ error: 'An account with this email already exists' });
        const hash = await bcrypt.hash(password, 10);
        const userId = await createUser(e, hash, 'user');
        const user = await getUserById(userId);
        if (!user) return res.status(500).json({ error: 'Registration failed' });
        (req.session as unknown as { userId: number }).userId = user.id;
        res.json({ user: { id: user.id, email: user.email, role: user.role } });
    } catch (e: unknown) {
        console.error('Register error:', e);
        if (isDbConnectionError(e)) {
            return res.status(503).json({ error: DB_UNAVAILABLE_MSG });
        }
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body as { email?: string; password?: string };
        if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Email and password required' });
        }
        const user = await getUserByEmail(email);
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        (req.session as unknown as { userId: number }).userId = user.id;
        res.json({ user: { id: user.id, email: user.email, role: user.role } });
    } catch (e: unknown) {
        console.error('Login error:', e);
        if (isDbConnectionError(e)) {
            return res.status(503).json({ error: DB_UNAVAILABLE_MSG });
        }
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/auth/me', (req: Request, res: Response) => {
    if (!req.user) {
        if (req.get('X-Silent-Session-Check') === '1') {
            return res.json({ user: null });
        }
        return res.status(401).json({ error: 'Not logged in' });
    }
    res.json({ user: { id: req.user.id, email: req.user.email, role: req.user.role } });
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout session destroy error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('connect.sid', { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
        res.json({ ok: true });
    });
});

// ----------------------------------------------------------------------------
// Temporary: test DB connection (remove in production if desired)
// ----------------------------------------------------------------------------
app.get('/api/test-db', async (_req: Request, res: Response) => {
    try {
        const result = await testConnection();
        res.json(result);
    } catch (e: unknown) {
        const err = e as { code?: string; message?: string; errno?: number };
        const code = err?.code ?? 'UNKNOWN';
        const msg = err?.message ?? String(e);
        console.error('Test DB failed:', code, msg);
        res.status(503).json({
            ok: false,
            error: 'Database connection failed',
            code,
            message: msg,
        });
    }
});

// Multer configuration
const storage = multer.diskStorage({
    destination: (
        _req: Request,
        _file: MulterFile,
        cb: (error: Error | null, destination: string) => void
    ) => {
        cb(null, PATHS.UPLOADS);
    },
    filename: (
        _req: Request,
        file: MulterFile,
        cb: (error: Error | null, filename: string) => void
    ) => {
        const timestamp = Date.now();
        const originalName = path.parse(file.originalname).name;
        const ext = path.extname(file.originalname);
        cb(null, `${originalName}-${timestamp}${ext}`);
    },
});

const fileFilter: multer.Options['fileFilter'] = (
    _req: Request,
    file: MulterFile,
    cb: multer.FileFilterCallback
): void => {
    if (FileUtils.isValidImageFile(file.originalname, file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'));
    }
};

const upload = multer({
    storage,
    limits: { fileSize: CONFIG.MAX_FILE_SIZE },
    fileFilter,
});

// ============================================================================
// API Routes
// ============================================================================

async function downloadImageToFile(imageUrl: string, destPath: string): Promise<void> {
    const url = new URL(imageUrl);
    const lib = url.protocol === 'https:' ? https : http;
    await new Promise<void>((resolve, reject) => {
        const req2 = lib.get(imageUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (r) => {
            const file = fs.createWriteStream(destPath);
            r.pipe(file);
            file.on('finish', () => { file.close(); resolve(); });
        });
        req2.on('error', reject);
    });
}

app.post(
    '/api/virtual-try-on',
    requireAuth,
    upload.fields([
        { name: 'personImage', maxCount: 1 },
        { name: 'productImage', maxCount: 1 },
    ]),
    async (req: Request, res: Response) => {
        try {
            const files = (req.files || {}) as { [fieldname: string]: Express.Multer.File[] };
            const body = req.body as { productImageUrl?: string };
            const generationId = Date.now();
            const userId = req.user!.id;

            if (!files.personImage?.[0]) {
                return res.status(400).json({ error: 'Person image is required' });
            }

            const personImage = files.personImage[0];
            const personExt = path.extname(personImage.filename);
            const personNewFilename = `person-${generationId}${personExt}`;
            const personNewPath = path.join(PATHS.UPLOADS, personNewFilename);
            fs.renameSync(personImage.path, personNewPath);

            let productNewPath: string;
            let productNewFilename: string;

            if (files.productImage?.[0]) {
                const productImage = files.productImage[0];
                const productExt = path.extname(productImage.filename);
                productNewFilename = `product-${generationId}${productExt}`;
                productNewPath = path.join(PATHS.UPLOADS, productNewFilename);
                fs.renameSync(productImage.path, productNewPath);
            } else if (body.productImageUrl && typeof body.productImageUrl === 'string') {
                productNewFilename = `product-${generationId}.jpg`;
                productNewPath = path.join(PATHS.UPLOADS, productNewFilename);
                await downloadImageToFile(body.productImageUrl, productNewPath);
            } else {
                return res.status(400).json({ error: 'Product image (file or URL) is required' });
            }

            // Get and validate sample count
            const sampleCount = parseInt(req.body.sampleCount || '1', 10);
            const validSampleCount = Math.max(1, Math.min(4, sampleCount));

            // Generate virtual try-on
            const predictions = await VirtualTryOnService.generateVirtualTryOn(
                personNewPath,
                productNewPath,
                validSampleCount
            );

            // Save generated images
            const savedImages: string[] = [];
            for (let i = 0; i < predictions.length; i++) {
                const prediction = predictions[i];
                const fileExtension = prediction.mimeType.split('/')[1] || 'png';
                const outputFilename = `result-${generationId}.${fileExtension}`;
                const outputPath = path.join(PATHS.OUTPUTS, outputFilename);

                const imageBuffer = Buffer.from(prediction.bytesBase64Encoded, 'base64');
                fs.writeFileSync(outputPath, imageBuffer);
                savedImages.push(`/outputs/${outputFilename}`);
            }

            const resultFilenames = savedImages.map((u) => path.basename(u));
            await insertTryOnHistory(userId, generationId, personNewFilename, productNewFilename, resultFilenames);

            res.json({
                success: true,
                id: generationId,
                personImageUrl: `/uploads/${personNewFilename}`,
                productImageUrl: `/uploads/${productNewFilename}`,
                resultImages: savedImages,
                count: savedImages.length,
            });
        } catch (error: any) {
            console.error('Error generating virtual try-on:', error);
            res.status(500).json({
                error: error.message || 'Failed to generate virtual try-on',
                details: error.toString(),
            });
        }
    }
);

// Extract product image from e-commerce URL
app.post('/api/extract-product', async (req: Request, res: Response) => {
    try {
        const { url } = req.body as { url?: string };
        if (!url || typeof url !== 'string') {
            return res.status(400).json({ error: 'URL is required' });
        }
        const parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return res.status(400).json({ error: 'Invalid URL protocol' });
        }

        const headers: Record<string, string> = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'identity',
            'Referer': parsed.origin + '/',
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

        if (html.includes('Site Maintenance') || html.includes('Something went wrong') || html.length < 1000) {
            return res.status(403).json({
                error: 'This site blocked the request or returned an error page. Try copying the product image URL directly or use a different site.',
            });
        }

        const $ = cheerio.load(html);
        let productImageUrl: string | null = null;

        const normalizeUrl = (src: string): string =>
            src.startsWith('//') ? 'https:' + src : src.startsWith('/') ? parsed.origin + src : src;

        // 1. Try og:image first (common for product pages)
        const ogImage = $('meta[property="og:image"]').attr('content');
        if (ogImage && ogImage.length > 10) {
            productImageUrl = normalizeUrl(ogImage);
        }

        // 2. Try JSON-LD product data (Myntra, Flipkart, etc. embed this)
        if (!productImageUrl) {
            $('script[type="application/ld+json"]').each((_, el) => {
                try {
                    const json = JSON.parse($(el).html() || '{}');
                    const item = json['@graph']?.[0] || json;
                    const img = item.image || item.thumbnailUrl;
                    if (typeof img === 'string' && img.length > 10) {
                        productImageUrl = normalizeUrl(img);
                        return false;
                    }
                    if (Array.isArray(img) && img[0]) {
                        productImageUrl = normalizeUrl(img[0]);
                        return false;
                    }
                } catch {
                    /* ignore */
                }
            });
        }

        // 3. Myntra-specific: imageContainer, pdp-image
        if (!productImageUrl && parsed.hostname.includes('myntra')) {
            const myntraSelectors = [
                'img[class*="image-container"]', 'img[class*="pdp-image"]', '.image-grid-image img',
                '[class*="ProductImage"] img', 'img[data-src]',
            ];
            for (const sel of myntraSelectors) {
                $(sel).each((_, el) => {
                    const src = $(el).attr('src') || $(el).attr('data-src');
                    if (src && (src.includes('myntra') || src.includes('cdn')) && !src.includes('logo')) {
                        productImageUrl = normalizeUrl(src);
                        return false;
                    }
                });
                if (productImageUrl) break;
            }
        }

        // 4. Fallback: find product-like images (src or data-src for lazy load)
        if (!productImageUrl) {
            const selectors = [
                'img[data-product-image]', 'img.product-image', '.product img', '.product-image img',
                '[class*="product"] img', '[class*="Product"] img', 'main img', '.gallery img', '.pdp-images img',
            ];
            const candidates: { src: string; size: number }[] = [];
            for (const sel of selectors) {
                $(sel).each((_, el) => {
                    const src = $(el).attr('src') || $(el).attr('data-src');
                    if (src && !src.includes('logo') && !src.includes('avatar') && src.match(/\.(jpg|jpeg|png|webp)/i)) {
                        const w = parseInt(String($(el).attr('width') || '0'), 10) || 300;
                        const h = parseInt(String($(el).attr('height') || '0'), 10) || 300;
                        const size = w * h;
                        candidates.push({ src: normalizeUrl(src), size });
                    }
                });
            }
            const bestImg = candidates.sort((a, b) => b.size - a.size)[0];
            if (bestImg) productImageUrl = bestImg.src;
        }

        if (!productImageUrl) {
            return res.status(404).json({ error: 'Could not find product image on this page' });
        }

        res.json({ productImageUrl });
    } catch (error: any) {
        console.error('Error extracting product:', error);
        res.status(500).json({ error: error.message || 'Failed to extract product image' });
    }
});

app.get('/api/results', requireAuth, async (req: Request, res: Response) => {
    try {
        const userId = req.user!.id;
        const isSuperadmin = req.user!.role === 'superadmin';
        const rows = await getTryOnHistoryByUser(userId, isSuperadmin);
        const uploadsDir = PATHS.UPLOADS;
        const outputsDir = PATHS.OUTPUTS;
        const results: VirtualTryOnResult[] = rows
            .map((row) => {
                const personPath = path.join(uploadsDir, row.person_filename);
                const productPath = path.join(uploadsDir, row.product_filename);
                let resultPaths: string[] = [];
                try {
                    resultPaths = Array.isArray(row.result_filenames)
                        ? (row.result_filenames as string[])
                        : (JSON.parse(row.result_filenames) as string[]);
                } catch {
                    resultPaths = [];
                }
                const firstResultPath = resultPaths[0] ? path.join(outputsDir, resultPaths[0]) : '';
                if (!fs.existsSync(personPath) || !fs.existsSync(productPath) || !fs.existsSync(firstResultPath)) {
                    return null;
                }
                const result: VirtualTryOnResult = {
                    id: row.generation_id,
                    personImageUrl: `/uploads/${row.person_filename}`,
                    productImageUrl: `/uploads/${row.product_filename}`,
                    resultImages: resultPaths.map((f) => `/outputs/${f}`),
                };
                if (isSuperadmin && (row as { user_email?: string }).user_email) {
                    result.userEmail = (row as { user_email: string }).user_email;
                }
                return result;
            })
            .filter((r): r is VirtualTryOnResult => r !== null);
        res.json({ results });
    } catch (error: any) {
        console.error('Error getting results:', error);
        res.status(500).json({
            error: error.message || 'Failed to get results',
            details: error.toString(),
        });
    }
});

app.delete('/api/results/:id', requireAuth, async (req: Request, res: Response) => {
    try {
        const generationId = parseInt(req.params.id, 10);
        if (Number.isNaN(generationId)) return res.status(400).json({ error: 'Invalid id' });
        const row = await getTryOnByGenerationId(generationId);
        if (!row) return res.status(404).json({ error: 'Result not found' });
        const isSuperadmin = req.user!.role === 'superadmin';
        if (row.user_id !== req.user!.id && !isSuperadmin) {
            return res.status(403).json({ error: 'You can only delete your own results' });
        }
        const uploadsDir = PATHS.UPLOADS;
        const outputsDir = PATHS.OUTPUTS;
        for (const filename of [row.person_filename, row.product_filename]) {
            const p = path.join(uploadsDir, filename);
            if (fs.existsSync(p)) fs.unlinkSync(p);
        }
        let resultFilenames: string[] = [];
        try {
            resultFilenames = Array.isArray(row.result_filenames)
                ? (row.result_filenames as string[])
                : (JSON.parse(row.result_filenames) as string[]);
        } catch {
            /* ignore */
        }
        for (const filename of resultFilenames) {
            const p = path.join(outputsDir, filename);
            if (fs.existsSync(p)) fs.unlinkSync(p);
        }
        await deleteTryOnHistory(generationId);
        res.json({ ok: true });
    } catch (error: any) {
        console.error('Error deleting result:', error);
        res.status(500).json({ error: error.message || 'Failed to delete' });
    }
});

// ============================================================================
// Server Startup
// ============================================================================

initializeApp();

async function seedSuperadminIfNeeded(): Promise<void> {
    try {
        const cnt = await countUsers();
        if (cnt > 0) return;
        const defaultPassword = 'admin123';
        const hash = await bcrypt.hash(defaultPassword, 10);
        await createUser('superadmin@zaha.ai', hash, 'superadmin');
        console.log('👤 Superadmin created: email=superadmin@zaha.ai, password=admin123 (change after first login)');
    } catch (e: unknown) {
        const err = e as { code?: string; message?: string };
        if (err?.code === 'ECONNREFUSED') {
            console.warn(
                '⚠️  MySQL connection refused. Login and history will not work until the database is reachable.\n' +
                '   If you run the app locally, the host auth-db1274.hstgr.io may only allow connections from your hosting provider.\n' +
                '   Deploy the app on the same host (e.g. Hostinger) or use a MySQL instance reachable from your network (e.g. localhost).'
            );
        } else {
            console.error('Could not seed superadmin:', err?.message ?? e);
        }
    }
}

app.listen(CONFIG.PORT, async () => {
    console.log(`🚀 Server running on http://localhost:${CONFIG.PORT}`);
    console.log(`📁 Uploads directory: ${PATHS.UPLOADS}`);
    console.log(`📁 Outputs directory: ${PATHS.OUTPUTS}`);
    console.log(process.env.DATABASE_URL ? '🔐 Sessions: PostgreSQL (persistent)' : '⚠️ Sessions: in-memory (set DATABASE_URL on Render for persistent login)');
    await seedSuperadminIfNeeded();
});

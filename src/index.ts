// Web server for Virtual Try-On interface
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import multer from 'multer';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import https from 'https';
import http from 'http';
import { GoogleAuth } from 'google-auth-library';
import * as cheerio from 'cheerio';

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
app.use(cors());
app.use(express.json());
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
    upload.fields([
        { name: 'personImage', maxCount: 1 },
        { name: 'productImage', maxCount: 1 },
    ]),
    async (req: Request, res: Response) => {
        try {
            const files = (req.files || {}) as { [fieldname: string]: Express.Multer.File[] };
            const body = req.body as { productImageUrl?: string };
            const generationId = Date.now();

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

        const html = await new Promise<string>((resolve, reject) => {
            const lib = parsed.protocol === 'https:' ? https : http;
            const req2 = lib.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } }, (r) => {
                let data = '';
                r.on('data', (ch) => { data += ch; });
                r.on('end', () => resolve(data));
            });
            req2.on('error', reject);
            req2.setTimeout(10000, () => { req2.destroy(); reject(new Error('Request timeout')); });
        });

        const $ = cheerio.load(html);
        let productImageUrl: string | null = null;

        // Try og:image first (common for product pages)
        const ogImage = $('meta[property="og:image"]').attr('content');
        if (ogImage) {
            productImageUrl = ogImage.startsWith('//') ? 'https:' + ogImage : ogImage;
        }

        // Fallback: find largest product-like image (common selectors)
        if (!productImageUrl) {
            const selectors = [
                'img[data-product-image]', 'img.product-image', '.product img', '.product-image img',
                '[class*="product"] img', '[id*="product"] img', 'main img', '.gallery img'
            ];
            const candidates: { src: string; size: number }[] = [];
            for (const sel of selectors) {
                $(sel).each((_, el) => {
                    const src = $(el).attr('src');
                    if (src && !src.includes('logo') && !src.includes('avatar')) {
                        const w = parseInt(String($(el).attr('width') || '0'), 10) || 200;
                        const h = parseInt(String($(el).attr('height') || '0'), 10) || 200;
                        const size = w * h;
                        const fullSrc = src.startsWith('//') ? 'https:' + src : src.startsWith('/') ? parsed.origin + src : src;
                        candidates.push({ src: fullSrc, size });
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

app.get('/api/results', (_req: Request, res: Response) => {
    try {
        const results = ResultService.getAllResults();
        res.json({ results });
    } catch (error: any) {
        console.error('Error getting results:', error);
        res.status(500).json({
            error: error.message || 'Failed to get results',
            details: error.toString(),
        });
    }
});

// ============================================================================
// Server Startup
// ============================================================================

initializeApp();

app.listen(CONFIG.PORT, () => {
    console.log(`🚀 Server running on http://localhost:${CONFIG.PORT}`);
    console.log(`📁 Uploads directory: ${PATHS.UPLOADS}`);
    console.log(`📁 Outputs directory: ${PATHS.OUTPUTS}`);
});

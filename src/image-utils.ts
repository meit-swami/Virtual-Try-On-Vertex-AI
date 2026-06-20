import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

/** Vertex AI virtual-try-on-001: JPEG/PNG only, max 10MB, reasonable dimensions */
const MAX_DIMENSION = 1536;
const JPEG_QUALITY = 88;

/**
 * Normalize any input image to JPEG suitable for Vertex AI Virtual Try-On.
 * Converts WebP/GIF/PNG, auto-orients, and caps dimensions.
 */
export async function prepareImageForVertexAI(inputPath: string, label = 'image'): Promise<string> {
    if (!fs.existsSync(inputPath)) {
        throw new Error(`${label} file not found`);
    }

    const stat = fs.statSync(inputPath);
    if (stat.size === 0) {
        throw new Error(`${label} file is empty`);
    }

    const outPath = inputPath.replace(/(\.[^./\\]+)?$/, '') + '-vertex.jpg';

    try {
        const meta = await sharp(inputPath).metadata();
        if (!meta.width || !meta.height) {
            throw new Error(`${label} could not be read as a valid image`);
        }

        const pixels = meta.width * meta.height;
        if (pixels > 50_000_000) {
            throw new Error(`${label} is too large (${meta.width}×${meta.height}). Use a photo under 7000×7000 pixels.`);
        }

        await sharp(inputPath)
            .rotate()
            .resize(MAX_DIMENSION, MAX_DIMENSION, { fit: 'inside', withoutEnlargement: true })
            .jpeg({ quality: JPEG_QUALITY, mozjpeg: true })
            .toFile(outPath);

        const outStat = fs.statSync(outPath);
        if (outStat.size > 10 * 1024 * 1024) {
            await sharp(outPath).jpeg({ quality: 75, mozjpeg: true }).toFile(outPath + '.tmp');
            fs.renameSync(outPath + '.tmp', outPath);
        }

        return outPath;
    } catch (e: unknown) {
        const msg = (e as Error).message || String(e);
        if (msg.includes('Input buffer') || msg.includes('unsupported')) {
            throw new Error(`${label} format is not supported. Please use JPG or PNG.`);
        }
        throw new Error(`Could not process ${label}: ${msg}`);
    }
}

export function cleanupPreparedImage(preparedPath: string, originalPath: string): void {
    if (preparedPath !== originalPath && preparedPath.endsWith('-vertex.jpg') && fs.existsSync(preparedPath)) {
        try { fs.unlinkSync(preparedPath); } catch { /* ignore */ }
    }
}

/** Prefer JPEG URL for Shopify CDN (Vertex AI does not accept WebP) */
export function preferJpegProductUrl(url: string): string {
    if (/\.webp(\?|$)/i.test(url) && (url.includes('cdn.shopify.com') || url.includes('/cdn/shop/'))) {
        return url.replace(/\.webp(\?|$)/i, '.jpg$1');
    }
    return url;
}

/** Pick file extension from URL */
export function extFromUrl(url: string): string {
    const pathname = new URL(url).pathname.toLowerCase();
    if (pathname.endsWith('.webp')) return '.webp';
    if (pathname.endsWith('.png')) return '.png';
    if (pathname.endsWith('.gif')) return '.gif';
    if (pathname.endsWith('.jpeg')) return '.jpeg';
    return '.jpg';
}

export async function downloadAndPrepareProductImage(
    imageUrl: string,
    destDir: string,
    generationId: number,
    downloadFn: (url: string, dest: string) => Promise<void>
): Promise<string> {
    const ext = extFromUrl(imageUrl);
    const rawPath = path.join(destDir, `product-${generationId}-raw${ext}`);
    await downloadFn(imageUrl, rawPath);
    const prepared = await prepareImageForVertexAI(rawPath, 'Product image');
    const finalPath = path.join(destDir, `product-${generationId}.jpg`);
    fs.copyFileSync(prepared, finalPath);
    cleanupPreparedImage(prepared, rawPath);
    if (rawPath !== finalPath && fs.existsSync(rawPath)) fs.unlinkSync(rawPath);
    return finalPath;
}

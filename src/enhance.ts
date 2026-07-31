// ============================================================================
// Image enhancement / fidelity pipeline for Virtual Try-On outputs
// ----------------------------------------------------------------------------
// Goal: get the generated try-on as close as possible to "person unchanged,
// only the outfit differs, delivered at 4K".
//
// IMPORTANT (honesty): Vertex AI virtual-try-on-001 is a *generative* model.
// It does not natively output 4K and cannot guarantee a pixel-perfect,
// 100%-unchanged face/body/background. This module raises fidelity as far as
// current tooling allows, in clearly separated, pluggable stages:
//
//   Stage A  4K super-resolution        (ALWAYS ON — sharp Lanczos default,
//                                         optional external super-res provider)
//   Stage B  Background/face lock-in     (OPT-IN — requires a segmentation
//                                         provider; see PRODUCTION_ROADMAP.md)
//
// Each stage degrades gracefully: if a provider is not configured or fails,
// the pipeline falls back to the previous best image rather than erroring the
// whole try-on.
// ============================================================================

import fs from 'fs';
import sharp from 'sharp';
import { runReplicate, downloadBuffer, toDataUri } from './replicate';

// 4K UHD long-edge target. 3840×2160 is "4K"; we scale the long edge to 3840
// and let the short edge follow the source aspect ratio.
const FOUR_K_LONG_EDGE = 3840;

export interface EnhanceOptions {
    /** Long-edge pixel target. Default 3840 (4K). */
    targetLongEdge?: number;
    /** Output format for the enhanced image. Default 'png' for lossless. */
    format?: 'png' | 'jpeg';
    /** JPEG quality when format='jpeg'. Default 95. */
    jpegQuality?: number;
}

export interface EnhanceResult {
    /** Absolute path to the enhanced image written to disk. */
    outputPath: string;
    /** Final pixel dimensions. */
    width: number;
    height: number;
    /** Which upscaler actually produced the result. */
    upscaler: 'replicate-real-esrgan' | 'sharp-lanczos';
    /** True if an external super-res provider was attempted but fell back. */
    fellBack: boolean;
}

function envFlag(name: string, def = false): boolean {
    const v = process.env[name];
    if (v == null) return def;
    return /^(1|true|yes|on)$/i.test(v.trim());
}

// ---------------------------------------------------------------------------
// Stage A — 4K super-resolution
// ---------------------------------------------------------------------------

/**
 * Deterministic, always-available 4K upscale using sharp (Lanczos3).
 * This genuinely reaches 4K resolution. It is an interpolating resize, so it
 * enlarges without inventing new detail — reliable and dependency-free.
 */
async function upscaleWithSharp(
    inputBuffer: Buffer,
    targetLongEdge: number
): Promise<{ buffer: Buffer; width: number; height: number }> {
    const meta = await sharp(inputBuffer).metadata();
    const w = meta.width ?? 0;
    const h = meta.height ?? 0;
    if (!w || !h) throw new Error('Enhance: could not read source image dimensions');

    const scale = targetLongEdge / Math.max(w, h);
    // Never downscale here — enhancement should only add resolution.
    const finalScale = scale > 1 ? scale : 1;
    const targetW = Math.round(w * finalScale);
    const targetH = Math.round(h * finalScale);

    const out = await sharp(inputBuffer)
        .resize(targetW, targetH, { kernel: sharp.kernel.lanczos3, fit: 'fill' })
        // A light sharpen counteracts the softness of pure interpolation.
        .sharpen({ sigma: 0.6 })
        .toBuffer();

    return { buffer: out, width: targetW, height: targetH };
}

/**
 * Optional detail-generating super-resolution via Replicate (Real-ESRGAN).
 * Enabled only when UPSCALE_PROVIDER=replicate and REPLICATE_API_TOKEN is set.
 * Returns a PNG buffer, or throws so the caller can fall back to sharp.
 */
async function upscaleWithReplicate(inputBuffer: Buffer): Promise<Buffer> {
    // Real-ESRGAN with face enhancement. Version pinned via env so upgrades are
    // an explicit, reviewable change rather than a silent one.
    const version =
        process.env.REPLICATE_UPSCALE_VERSION ||
        'f121d640bd286e1fdc67f9799164c1d5be36ff74576ee11c803ae5b665dd46aa'; // nightmareai/real-esrgan

    const output = await runReplicate(version, {
        image: toDataUri(inputBuffer),
        scale: 4,
        face_enhance: true,
    });

    const url = Array.isArray(output) ? output[0] : output;
    if (!url) throw new Error('Replicate super-res returned no output');
    return downloadBuffer(url);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Enhance a generated try-on image to 4K, writing the result to `outputPath`.
 *
 * @param inputPath   Path to the raw generated image (from Vertex AI).
 * @param outputPath  Path to write the enhanced image to.
 */
export async function enhanceToHighRes(
    inputPath: string,
    outputPath: string,
    options: EnhanceOptions = {}
): Promise<EnhanceResult> {
    const targetLongEdge = options.targetLongEdge ?? FOUR_K_LONG_EDGE;
    const format = options.format ?? 'png';
    const jpegQuality = options.jpegQuality ?? 95;

    const inputBuffer = fs.readFileSync(inputPath);

    let workingBuffer: Buffer = inputBuffer;
    let upscaler: EnhanceResult['upscaler'] = 'sharp-lanczos';
    let fellBack = false;

    // Stage A: external super-res first (if configured), else sharp.
    if (envFlag('UPSCALE_ENABLED', true) && (process.env.UPSCALE_PROVIDER || '').toLowerCase() === 'replicate') {
        try {
            workingBuffer = await upscaleWithReplicate(inputBuffer);
            upscaler = 'replicate-real-esrgan';
        } catch (e) {
            console.warn('[enhance] Replicate super-res failed, falling back to sharp:', (e as Error).message);
            fellBack = true;
        }
    }

    // Ensure we reach the 4K target regardless of provider (Real-ESRGAN's ×4 may
    // over- or under-shoot depending on source size; sharp normalizes to target).
    const finalized = await upscaleWithSharp(workingBuffer, targetLongEdge);

    let pipeline = sharp(finalized.buffer);
    if (format === 'jpeg') {
        pipeline = pipeline.jpeg({ quality: jpegQuality, mozjpeg: true });
    } else {
        pipeline = pipeline.png({ compressionLevel: 9 });
    }
    await pipeline.toFile(outputPath);

    return {
        outputPath,
        width: finalized.width,
        height: finalized.height,
        upscaler,
        fellBack,
    };
}

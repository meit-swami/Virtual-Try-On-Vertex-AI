// ============================================================================
// Fidelity pipeline — Stage B (background lock-in) + Stage C (face restore)
// ----------------------------------------------------------------------------
// These stages push the generated try-on closer to "the person is unchanged,
// only the outfit differs":
//
//   Stage B  Background lock-in — segment the person out of the GENERATED image
//            and composite them back onto the ORIGINAL photo's background, so
//            the real background is preserved rather than regenerated.
//
//   Stage C  Face restoration — run a face-restoration model over the result to
//            counteract identity/expression drift introduced by generation.
//
// Both require a segmentation / restoration provider (Replicate) and are
// therefore OFF by default. When disabled or unconfigured, they no-op and the
// original generated image passes through untouched — nothing breaks.
//
// HONESTY: even with these stages, output is "visually near-identical", not a
// mathematically guaranteed 100% pixel match. Pose shifts from the generative
// model can cause minor edge blending at the person boundary.
// ============================================================================

import fs from 'fs';
import sharp from 'sharp';
import { runReplicate, downloadBuffer, toDataUri, isReplicateConfigured } from './replicate';

function envFlag(name: string, def = false): boolean {
    const v = process.env[name];
    if (v == null) return def;
    return /^(1|true|yes|on)$/i.test(v.trim());
}

// ---------------------------------------------------------------------------
// Stage B — background lock-in
// ---------------------------------------------------------------------------

/**
 * Segment the foreground person out of an image, returning an RGBA PNG cutout
 * (person opaque, background transparent). Uses a Replicate background-removal
 * model. Throws if the provider fails so the caller can fall back.
 */
async function removeBackground(inputBuffer: Buffer): Promise<Buffer> {
    const version =
        process.env.REPLICATE_REMBG_VERSION ||
        'fb8af171cfa1616ddcf1242c093f9c46bcada5ad4cf6f2fbe8b81b330ec5c003'; // cjwbw/rembg

    const output = await runReplicate(version, { image: toDataUri(inputBuffer) });
    const url = Array.isArray(output) ? output[0] : output;
    if (!url) throw new Error('Background removal returned no output');
    return downloadBuffer(url);
}

/**
 * Composite the person from `generatedBuffer` onto the background of
 * `originalPersonPath`, preserving the original photo's real background pixels.
 */
export async function lockBackgroundToOriginal(
    generatedBuffer: Buffer,
    originalPersonPath: string
): Promise<Buffer> {
    const meta = await sharp(generatedBuffer).metadata();
    const W = meta.width ?? 0;
    const H = meta.height ?? 0;
    if (!W || !H) throw new Error('Background lock: could not read generated dimensions');

    // 1. Cut the person out of the generated try-on.
    const cutoutRaw = await removeBackground(generatedBuffer);
    // Normalize the cutout to the generated dimensions (rembg usually preserves
    // them, but be defensive so the composite always aligns).
    const cutout = await sharp(cutoutRaw).resize(W, H, { fit: 'fill' }).png().toBuffer();

    // 2. Use the ORIGINAL photo, scaled to cover the frame, as the background.
    const background = await sharp(originalPersonPath)
        .rotate() // respect EXIF
        .resize(W, H, { fit: 'cover' })
        .toBuffer();

    // 3. Composite the generated (re-dressed) person over the original background.
    return sharp(background).composite([{ input: cutout, blend: 'over' }]).png().toBuffer();
}

// ---------------------------------------------------------------------------
// Stage C — face restoration
// ---------------------------------------------------------------------------

/**
 * Run a face-restoration model (CodeFormer) to reduce identity/expression drift.
 * Returns the restored image buffer, or throws for caller fallback.
 */
export async function restoreFace(inputBuffer: Buffer): Promise<Buffer> {
    const version =
        process.env.REPLICATE_FACE_RESTORE_VERSION ||
        '7de2ea26c616d5bf2245ad0d5e24f0ff9a6204578a5c876db53142edd9d2cd56'; // sczhou/codeformer

    const fidelity = Number(process.env.FACE_RESTORE_FIDELITY ?? 0.9); // 0..1, higher = closer to input
    const output = await runReplicate(version, {
        image: toDataUri(inputBuffer),
        codeformer_fidelity: Math.max(0, Math.min(1, fidelity)),
        background_enhance: false, // we protect the background ourselves in Stage B
        face_upsample: true,
        upscale: 1,
    });
    const url = Array.isArray(output) ? output[0] : output;
    if (!url) throw new Error('Face restoration returned no output');
    return downloadBuffer(url);
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/**
 * Apply the enabled fidelity stages to a generated try-on image and write the
 * result to `outputPath`. Returns the path actually written (always outputPath).
 * Every stage degrades gracefully to the previous best buffer on failure.
 */
export async function applyFidelity(
    generatedPath: string,
    originalPersonPath: string,
    outputPath: string
): Promise<{ outputPath: string; stagesApplied: string[] }> {
    let buffer: Buffer = fs.readFileSync(generatedPath);
    const stagesApplied: string[] = [];

    const wantBgLock = envFlag('BACKGROUND_LOCK_ENABLED', false);
    const wantFaceRestore = envFlag('FACE_RESTORE_ENABLED', false);

    if ((wantBgLock || wantFaceRestore) && !isReplicateConfigured()) {
        console.warn('[fidelity] BACKGROUND_LOCK/FACE_RESTORE requested but REPLICATE_API_TOKEN is not set — skipping.');
    }

    if (wantBgLock && isReplicateConfigured()) {
        try {
            buffer = await lockBackgroundToOriginal(buffer, originalPersonPath);
            stagesApplied.push('background-lock');
        } catch (e) {
            console.warn('[fidelity] background lock failed, keeping generated background:', (e as Error).message);
        }
    }

    if (wantFaceRestore && isReplicateConfigured()) {
        try {
            buffer = await restoreFace(buffer);
            stagesApplied.push('face-restore');
        } catch (e) {
            console.warn('[fidelity] face restore failed, keeping generated face:', (e as Error).message);
        }
    }

    fs.writeFileSync(outputPath, buffer);
    return { outputPath, stagesApplied };
}

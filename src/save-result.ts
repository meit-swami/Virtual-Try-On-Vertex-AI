// Shared helper: persist a Vertex AI prediction to disk, running the fidelity
// stages (background lock-in, face restore) and 4K enhancement. Used by both
// the main app route and plugin routes so behaviour is identical everywhere.
//
// Pipeline order per image:
//   raw generated → [Stage B background lock] → [Stage C face restore] → [Stage A 4K] → saved

import fs from 'fs';
import path from 'path';
import { enhanceToHighRes } from './enhance';
import { applyFidelity } from './fidelity';

interface Prediction {
    mimeType: string;
    bytesBase64Encoded: string;
}

function envFlag(name: string, def = false): boolean {
    const v = process.env[name];
    if (v == null) return def;
    return /^(1|true|yes|on)$/i.test(v.trim());
}

/**
 * Save all predictions for a generation, returning the public `/outputs/...`
 * URLs.
 *
 * @param originalPersonPath  Path to the user's uploaded person photo, needed
 *                            by the background lock-in stage. Optional; if
 *                            omitted, background lock is skipped.
 */
export async function savePredictions(
    predictions: Prediction[],
    outputsDir: string,
    generationId: number,
    originalPersonPath?: string
): Promise<string[]> {
    const enhance = envFlag('UPSCALE_ENABLED', true);
    const runFidelity =
        !!originalPersonPath &&
        (envFlag('BACKGROUND_LOCK_ENABLED', false) || envFlag('FACE_RESTORE_ENABLED', false));
    const savedImages: string[] = [];

    for (let i = 0; i < predictions.length; i++) {
        const prediction = predictions[i];
        const rawExt = prediction.mimeType.split('/')[1] || 'png';
        const suffix = predictions.length > 1 ? `-${i + 1}` : '';
        const imageBuffer = Buffer.from(prediction.bytesBase64Encoded, 'base64');

        // Fast path: nothing to do — write raw and move on.
        if (!enhance && !runFidelity) {
            const outputFilename = `result-${generationId}${suffix}.${rawExt}`;
            fs.writeFileSync(path.join(outputsDir, outputFilename), imageBuffer);
            savedImages.push(`/outputs/${outputFilename}`);
            continue;
        }

        const rawPath = path.join(outputsDir, `result-${generationId}${suffix}-raw.${rawExt}`);
        fs.writeFileSync(rawPath, imageBuffer);

        // Track the "current best" file through the stages so failures can fall back.
        let currentPath = rawPath;
        const tempFiles: string[] = [rawPath];

        try {
            // Stage B + C — fidelity (background lock-in, face restore).
            if (runFidelity) {
                const fidelityPath = path.join(outputsDir, `result-${generationId}${suffix}-fidelity.png`);
                const { stagesApplied } = await applyFidelity(currentPath, originalPersonPath!, fidelityPath);
                if (stagesApplied.length > 0) {
                    currentPath = fidelityPath;
                    tempFiles.push(fidelityPath);
                    console.log(`[fidelity] ${path.basename(fidelityPath)}: applied ${stagesApplied.join(', ')}`);
                }
            }

            // Stage A — 4K enhancement (final output).
            const outputFilename = `result-${generationId}${suffix}.png`;
            const outputPath = path.join(outputsDir, outputFilename);

            if (enhance) {
                const result = await enhanceToHighRes(currentPath, outputPath, { format: 'png' });
                console.log(
                    `[enhance] ${outputFilename}: ${result.width}×${result.height} via ${result.upscaler}` +
                    (result.fellBack ? ' (fell back to sharp)' : '')
                );
            } else {
                // Fidelity ran but 4K disabled — promote the fidelity result.
                fs.copyFileSync(currentPath, outputPath);
            }
            savedImages.push(`/outputs/${outputFilename}`);
        } catch (e) {
            // Any stage failed — fall back to the raw generated image.
            console.warn(`[save] pipeline failed for generation ${generationId}${suffix}, using raw:`, (e as Error).message);
            const fallbackName = `result-${generationId}${suffix}.${rawExt}`;
            fs.copyFileSync(rawPath, path.join(outputsDir, fallbackName));
            savedImages.push(`/outputs/${fallbackName}`);
        } finally {
            // Clean up intermediates (keep only the final saved output).
            for (const f of tempFiles) {
                try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch { /* ignore */ }
            }
        }
    }

    return savedImages;
}

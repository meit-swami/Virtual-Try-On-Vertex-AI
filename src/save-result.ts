// Shared helper: persist a Vertex AI prediction to disk, optionally running the
// 4K enhancement pipeline. Used by both the main app route and plugin routes so
// the output behaviour is identical everywhere.

import fs from 'fs';
import path from 'path';
import { enhanceToHighRes } from './enhance';

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
 * URLs. When UPSCALE_ENABLED (default true), each image is enhanced to 4K.
 */
export async function savePredictions(
    predictions: Prediction[],
    outputsDir: string,
    generationId: number
): Promise<string[]> {
    const enhance = envFlag('UPSCALE_ENABLED', true);
    const savedImages: string[] = [];

    for (let i = 0; i < predictions.length; i++) {
        const prediction = predictions[i];
        const rawExt = prediction.mimeType.split('/')[1] || 'png';
        // Suffix multi-sample results so they never overwrite each other.
        const suffix = predictions.length > 1 ? `-${i + 1}` : '';
        const imageBuffer = Buffer.from(prediction.bytesBase64Encoded, 'base64');

        if (!enhance) {
            const outputFilename = `result-${generationId}${suffix}.${rawExt}`;
            fs.writeFileSync(path.join(outputsDir, outputFilename), imageBuffer);
            savedImages.push(`/outputs/${outputFilename}`);
            continue;
        }

        // Write the raw model output to a temp file, enhance to a 4K PNG.
        const rawPath = path.join(outputsDir, `result-${generationId}${suffix}-raw.${rawExt}`);
        fs.writeFileSync(rawPath, imageBuffer);
        const outputFilename = `result-${generationId}${suffix}.png`;
        const outputPath = path.join(outputsDir, outputFilename);

        try {
            const result = await enhanceToHighRes(rawPath, outputPath, { format: 'png' });
            console.log(
                `[enhance] ${outputFilename}: ${result.width}×${result.height} via ${result.upscaler}` +
                (result.fellBack ? ' (fell back to sharp)' : '')
            );
        } catch (e) {
            // If enhancement fails for any reason, fall back to the raw image so
            // the customer still gets a result.
            console.warn(`[enhance] failed for ${outputFilename}, using raw output:`, (e as Error).message);
            const fallbackName = `result-${generationId}${suffix}.${rawExt}`;
            fs.copyFileSync(rawPath, path.join(outputsDir, fallbackName));
            savedImages.push(`/outputs/${fallbackName}`);
            try { fs.unlinkSync(rawPath); } catch { /* ignore */ }
            continue;
        }

        try { fs.unlinkSync(rawPath); } catch { /* ignore */ }
        savedImages.push(`/outputs/${outputFilename}`);
    }

    return savedImages;
}

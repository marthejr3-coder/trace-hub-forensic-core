/**
 * Streaming SHA-256 hashing usando hash-wasm para arquivos grandes (até 900 MB)
 * sem estourar a memória do navegador.
 */
import { createSHA256 } from 'hash-wasm';

const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB

export async function hashFileSHA256(
  file: File | Blob,
  onProgress?: (loaded: number, total: number) => void,
): Promise<string> {
  const hasher = await createSHA256();
  hasher.init();

  let offset = 0;
  const total = file.size;
  while (offset < total) {
    const slice = file.slice(offset, Math.min(offset + CHUNK_SIZE, total));
    const buf = new Uint8Array(await slice.arrayBuffer());
    hasher.update(buf);
    offset += buf.byteLength;
    onProgress?.(offset, total);
    // yield to UI
    await new Promise(r => setTimeout(r, 0));
  }

  return hasher.digest('hex');
}

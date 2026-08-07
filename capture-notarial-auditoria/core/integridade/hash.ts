/**
 * Primitivas de hash do Sistema de Integridade Forense Avançada.
 * Requisito 15: SHA-256 para todos os hashes, timestamps UTC ISO-8601.
 */

export function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function sha256Hex(input: string | ArrayBuffer | Uint8Array): Promise<string> {
  const data =
    typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return toHex(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

/* ------------------------------------------------------------------ *
 * SHA-256 incremental (JS puro).
 *
 * A WebCrypto só digere um buffer inteiro de uma vez: hashear um vídeo de
 * centenas de MB obriga `blob.arrayBuffer()` a materializar tudo em um bloco
 * contíguo, o que estoura a memória da aba (Chrome "página sem resposta").
 * Esta implementação consome fatias e produz EXATAMENTE o mesmo digest.
 * ------------------------------------------------------------------ */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export class Sha256Stream {
  private h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  private buffer = new Uint8Array(64);
  private bufferLen = 0;
  private totalLen = 0;
  private w = new Uint32Array(64);

  private compress(block: Uint8Array, offset: number) {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3];
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    const h = this.h;
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }

  update(chunk: Uint8Array): void {
    this.totalLen += chunk.length;
    let offset = 0;
    if (this.bufferLen > 0) {
      const need = 64 - this.bufferLen;
      const take = Math.min(need, chunk.length);
      this.buffer.set(chunk.subarray(0, take), this.bufferLen);
      this.bufferLen += take;
      offset = take;
      if (this.bufferLen === 64) {
        this.compress(this.buffer, 0);
        this.bufferLen = 0;
      }
    }
    while (offset + 64 <= chunk.length) {
      this.compress(chunk, offset);
      offset += 64;
    }
    if (offset < chunk.length) {
      this.buffer.set(chunk.subarray(offset), 0);
      this.bufferLen = chunk.length - offset;
    }
  }

  digestHex(): string {
    const bitLen = this.totalLen * 8;
    const padLen = this.bufferLen < 56 ? 56 - this.bufferLen : 120 - this.bufferLen;
    const tail = new Uint8Array(this.bufferLen + padLen + 8);
    tail.set(this.buffer.subarray(0, this.bufferLen), 0);
    tail[this.bufferLen] = 0x80;
    const view = new DataView(tail.buffer);
    // Comprimento em bits (64 bits big-endian); suporta > 4 GB via float seguro.
    view.setUint32(tail.length - 8, Math.floor(bitLen / 0x100000000));
    view.setUint32(tail.length - 4, bitLen >>> 0);
    for (let i = 0; i < tail.length; i += 64) this.compress(tail, i);
    let out = '';
    for (let i = 0; i < 8; i++) out += this.h[i].toString(16).padStart(8, '0');
    return out;
  }
}

/** Fatia usada para ler Blobs grandes sem materializá-los inteiros na memória. */
const BLOB_SLICE_BYTES = 8 * 1024 * 1024;

/**
 * SHA-256 de um Blob lido em fatias de 8 MB, cedendo o controle ao navegador
 * entre as fatias. Blobs pequenos usam a WebCrypto direto (mais rápido).
 */
export async function sha256OfBlob(blob: Blob): Promise<string> {
  if (blob.size <= BLOB_SLICE_BYTES) {
    return sha256Hex(await blob.arrayBuffer());
  }
  const stream = new Sha256Stream();
  for (let offset = 0; offset < blob.size; offset += BLOB_SLICE_BYTES) {
    const slice = blob.slice(offset, Math.min(offset + BLOB_SLICE_BYTES, blob.size));
    const buf = await slice.arrayBuffer();
    stream.update(new Uint8Array(buf));
    // Devolve a thread principal ao navegador para a aba não congelar.
    await new Promise<void>((r) => setTimeout(r, 0));
  }
  return stream.digestHex();
}

/** Timestamp canônico UTC ISO-8601 (com milissegundos + Z). */
export function utcNow(): string {
  return new Date().toISOString();
}

/** JSON canônico determinístico (chaves ordenadas em todos os níveis). */
export function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return '[' + value.map(canonicalStringify).join(',') + ']';
  const obj = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalStringify(obj[k]))
      .join(',') +
    '}'
  );
}

/** Hash canônico de um objeto JSON (independente da ordem das chaves). */
export async function sha256OfJson(value: unknown): Promise<string> {
  return sha256Hex(canonicalStringify(value));
}

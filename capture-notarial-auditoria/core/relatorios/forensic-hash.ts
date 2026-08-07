/**
 * Forensic Hash Module
 * Generates SHA-256 + SHA-512 (FIPS 180-4) hashes for evidence integrity.
 * Dual-hash approach mirrors industry benchmark (Verifact / ISO 27037).
 */

async function digestHex(algo: 'SHA-256' | 'SHA-512', data: BufferSource): Promise<string> {
  const hashBuffer = await crypto.subtle.digest(algo, data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function generateSHA256(data: string): Promise<string> {
  return digestHex('SHA-256', new TextEncoder().encode(data));
}

export async function generateSHA512(data: string): Promise<string> {
  return digestHex('SHA-512', new TextEncoder().encode(data));
}

export interface EvidenceHashResult {
  hash: string;          // SHA-256 (retrocompatível com /verificar-evidencia)
  hash_sha512: string;   // SHA-512 (paridade Verifact / ISO 27037)
  timestamp: string;
  algorithm: string;     // "SHA-256 + SHA-512 (FIPS 180-4)"
  data_snapshot: string;
}

export async function generateEvidenceHash(
  evidence: Record<string, any>,
): Promise<EvidenceHashResult> {
  const timestamp = new Date().toISOString();
  const sortedData = JSON.stringify(evidence, Object.keys(evidence).sort());
  const dataWithTimestamp = `${sortedData}|${timestamp}`;
  const [hash, hash_sha512] = await Promise.all([
    generateSHA256(dataWithTimestamp),
    generateSHA512(dataWithTimestamp),
  ]);
  return {
    hash,
    hash_sha512,
    timestamp,
    algorithm: 'SHA-256 + SHA-512 (FIPS 180-4)',
    data_snapshot: sortedData,
  };
}

export async function verifyEvidenceHash(
  evidence: Record<string, any>,
  originalHash: string,
  originalTimestamp: string,
  variant: 'sha256' | 'sha512' = 'sha256',
): Promise<boolean> {
  // F-08 (laudo Jun/2026): validação explícita do timestamp ISO 8601 — evita
  // resultado "false" silencioso quando o timestamp está malformado.
  if (typeof originalTimestamp !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+\-]\d{2}:?\d{2})$/.test(originalTimestamp)) {
    throw new Error('verifyEvidenceHash: originalTimestamp não é ISO 8601 válido');
  }
  if (Number.isNaN(Date.parse(originalTimestamp))) {
    throw new Error('verifyEvidenceHash: originalTimestamp não pôde ser parseado');
  }
  const sortedData = JSON.stringify(evidence, Object.keys(evidence).sort());
  const dataWithTimestamp = `${sortedData}|${originalTimestamp}`;
  const computed = variant === 'sha512'
    ? await generateSHA512(dataWithTimestamp)
    : await generateSHA256(dataWithTimestamp);
  return computed === originalHash;
}

export function formatHashForDisplay(hash: string): string {
  return hash.match(/.{1,8}/g)?.join(':') || hash;
}

export async function hashFile(file: File): Promise<string> {
  return digestHex('SHA-256', await file.arrayBuffer());
}

/**
 * Dual-hash de um arquivo (SHA-256 + SHA-512).
 *
 * Para arquivos pequenos (≤ 40 MB) mantém o caminho rápido: carrega uma vez em
 * memória e roda os dois digests em paralelo.
 *
 * Para arquivos grandes (>40 MB típico de exports de Telegram .html/.json), o
 * caminho em paralelo causa OOM/freeze no Chrome mobile (a barra de upload
 * congelava em 30%). Rodamos SHA-256 e SHA-512 em série e, se SHA-512 falhar
 * ou estourar memória, devolvemos string vazia — a edge function
 * `verify-evidence-hash` rehasheia o blob no servidor e atualiza o registro.
 */
const DUAL_HASH_INLINE_LIMIT = 40 * 1024 * 1024;

export async function hashFileDual(file: File): Promise<{ sha256: string; sha512: string }> {
  if (file.size <= DUAL_HASH_INLINE_LIMIT) {
    const buf = await file.arrayBuffer();
    const [sha256, sha512] = await Promise.all([
      digestHex('SHA-256', buf),
      digestHex('SHA-512', buf),
    ]);
    return { sha256, sha512 };
  }

  // Caminho resiliente: serial, libera o buffer entre passes.
  let sha256 = '';
  try {
    const buf1 = await file.arrayBuffer();
    sha256 = await digestHex('SHA-256', buf1);
  } catch (e) {
    console.error('[hashFileDual] SHA-256 falhou em arquivo grande:', e);
    throw new Error('Não foi possível calcular o hash do arquivo. Tente novamente ou reduza o tamanho.');
  }

  let sha512 = '';
  try {
    const buf2 = await file.arrayBuffer();
    sha512 = await digestHex('SHA-512', buf2);
  } catch (e) {
    // SHA-512 é opcional no client; o servidor vai preencher via verify-evidence-hash.
    console.warn('[hashFileDual] SHA-512 client-side pulado (arquivo grande). Servidor irá calcular.', e);
    sha512 = '';
  }

  return { sha256, sha512 };
}


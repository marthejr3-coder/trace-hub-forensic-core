/**
 * PDF Self-Hash — Selo Interno Verificável
 *
 * Calcula o SHA-256 dos bytes finais do PDF e gera um arquivo companion
 * `.sha256.txt` no formato padrão `sha256sum` (compatível com a CLI:
 * `sha256sum -c arquivo.pdf.sha256.txt`).
 *
 * Atende ponto levantado no laudo pericial Jun/2026: o PDF agora carrega
 * prova externa da própria integridade, não apenas dos artefatos internos.
 */
import { downloadBlob } from './ios-download';

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export interface PdfSelfHashResult {
  sha256: string;
  sha512: string;
  sidecarBlob: Blob;
  sidecarFilename: string;
  verifyCommand: string;
}

/**
 * Gera o sidecar `.sha256.txt` a partir de um blob de PDF.
 */
export async function computePdfSelfHash(
  pdfBlob: Blob,
  pdfFilename: string,
): Promise<PdfSelfHashResult> {
  const bytes = await pdfBlob.arrayBuffer();
  const [sha256Buf, sha512Buf] = await Promise.all([
    crypto.subtle.digest('SHA-256', bytes),
    crypto.subtle.digest('SHA-512', bytes),
  ]);
  const sha256 = toHex(sha256Buf);
  const sha512 = toHex(sha512Buf);
  const sidecarFilename = `${pdfFilename}.sha256.txt`;
  const sidecarText =
    `# Trace Hub — Selo de integridade externo\n` +
    `# Verifique com:  sha256sum -c "${sidecarFilename}"\n` +
    `# Ou manualmente: sha256sum "${pdfFilename}"\n` +
    `${sha256}  ${pdfFilename}\n` +
    `# SHA-512: ${sha512}\n` +
    `# Gerado em: ${new Date().toISOString()}\n`;
  const sidecarBlob = new Blob([sidecarText], { type: 'text/plain' });
  return {
    sha256,
    sha512,
    sidecarBlob,
    sidecarFilename,
    verifyCommand: `sha256sum -c "${sidecarFilename}"`,
  };
}

/**
 * Baixa o PDF + o sidecar `.sha256.txt` lado-a-lado.
 * Usa um delay curto entre os downloads pra evitar bloqueio do navegador.
 */
export async function downloadPdfWithSelfHash(
  pdfBlob: Blob,
  pdfFilename: string,
  popup?: Window | null,
): Promise<PdfSelfHashResult> {
  const result = await computePdfSelfHash(pdfBlob, pdfFilename);
  downloadBlob(pdfBlob, pdfFilename, popup);
  // Pequeno delay para o browser processar o primeiro download antes do segundo.
  await new Promise((r) => setTimeout(r, 350));
  downloadBlob(result.sidecarBlob, result.sidecarFilename);
  return result;
}

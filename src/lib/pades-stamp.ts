/**
 * Aposição de CARIMBO FORENSE VISUAL em PDF externo.
 *
 * IMPORTANTE (F-09 do laudo de auditoria forense Jun/2026):
 * Este módulo NÃO implementa assinatura digital PAdES/CAdES real
 * (RSA/ECDSA + cadeia X.509). É um overlay visual com hash SHA-256
 * incorporado e QR de verificação. A garantia de integridade vem do
 * hash SHA-256 e da ancoragem temporal (OpenTimestamps + RFC 3161),
 * NÃO de uma assinatura PAdES no sentido ETSI EN 319 142.
 *
 * - Calcula SHA-256 do PDF original
 * - Adiciona overlay com responsável, data/hora, hash e QR de verificação
 * - Retorna novo Blob PDF
 */
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import QRCode from 'qrcode';

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

export interface ForensicVisualStampInput {
  pdfFile: File;
  responsibleName: string;
  verificationBaseUrl?: string; // default: window.location.origin + /verificar-evidencia
}

export interface ForensicVisualStampResult {
  pdfBlob: Blob;
  originalSha256: string;
  stampedSha256: string;
  verificationUrl: string;
  signedAt: string;
}

// Aliases retrocompatíveis (código existente importa PadesInput/PadesResult/applyPadesStamp)
export type PadesInput = ForensicVisualStampInput;
export type PadesResult = ForensicVisualStampResult;

export async function applyForensicVisualStamp(input: ForensicVisualStampInput): Promise<ForensicVisualStampResult> {
  const buf = await input.pdfFile.arrayBuffer();
  const originalSha256 = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', buf)));
  const signedAt = new Date().toISOString();

  const baseUrl = input.verificationBaseUrl
    || `${window.location.origin}/verificar-evidencia`;
  const verificationUrl = `${baseUrl}?hash=${originalSha256}`;

  const qrDataUrl = await QRCode.toDataURL(verificationUrl, { errorCorrectionLevel: 'M', margin: 1, width: 240 });
  const qrPng = await fetch(qrDataUrl).then(r => r.arrayBuffer());

  const pdf = await PDFDocument.load(buf, { ignoreEncryption: true });
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const qrImage = await pdf.embedPng(qrPng);

  const pages = pdf.getPages();
  const last = pages[pages.length - 1];
  const { width } = last.getSize();

  const boxW = 240, boxH = 100;
  const x = width - boxW - 20, y = 20;
  last.drawRectangle({
    x, y, width: boxW, height: boxH,
    color: rgb(0.97, 0.99, 0.98),
    borderColor: rgb(0.06, 0.5, 0.35),
    borderWidth: 1,
  });
  last.drawText('CARIMBO FORENSE VISUAL — TRACE HUB', {
    x: x + 8, y: y + boxH - 14, size: 8, font: fontBold, color: rgb(0.02, 0.4, 0.28),
  });
  last.drawText('Integridade: SHA-256 (não é assinatura PAdES)', {
    x: x + 8, y: y + boxH - 24, size: 6, font, color: rgb(0.35, 0.35, 0.35),
  });
  last.drawText(`Resp.: ${input.responsibleName.slice(0, 38)}`, {
    x: x + 8, y: y + boxH - 36, size: 7, font, color: rgb(0.1, 0.1, 0.1),
  });
  last.drawText(`Data: ${new Date(signedAt).toLocaleString('pt-BR')}`, {
    x: x + 8, y: y + boxH - 48, size: 7, font, color: rgb(0.1, 0.1, 0.1),
  });
  last.drawText('SHA-256:', { x: x + 8, y: y + boxH - 60, size: 7, font: fontBold, color: rgb(0.1, 0.1, 0.1) });
  last.drawText(originalSha256.slice(0, 32), { x: x + 8, y: y + boxH - 70, size: 6, font, color: rgb(0.2, 0.2, 0.2) });
  last.drawText(originalSha256.slice(32), { x: x + 8, y: y + boxH - 78, size: 6, font, color: rgb(0.2, 0.2, 0.2) });
  last.drawText('Verifique →', { x: x + 8, y: y + 8, size: 6, font, color: rgb(0.4, 0.4, 0.4) });
  last.drawImage(qrImage, { x: x + boxW - 70, y: y + 14, width: 62, height: 62 });

  const out = await pdf.save();
  const outCopy = new Uint8Array(out);
  const blob = new Blob([outCopy], { type: 'application/pdf' });
  const stampedSha256 = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', outCopy)));
  return { pdfBlob: blob, originalSha256, stampedSha256, verificationUrl, signedAt };
}

/**
 * @deprecated Use `applyForensicVisualStamp`. Nome anterior induzia erro em juízo
 * por sugerir assinatura PAdES real — corrigido conforme F-09 do laudo Jun/2026.
 */
export const applyPadesStamp = applyForensicVisualStamp;

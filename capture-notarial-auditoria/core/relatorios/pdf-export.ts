/**
 * Helper for exporting forensic reports as PDF using html2canvas + jsPDF.
 * Compatível com iOS Safari via `popup` opcional capturado dentro do gesture.
 */
import { getJsPDF, getHtml2Canvas } from '@/lib/jspdf-safe';
import { downloadBlob } from './ios-download';

async function buildPdf(element: HTMLElement) {
  const html2canvas = getHtml2Canvas();
  const jsPDF = getJsPDF();

  const canvas = await html2canvas(element, {
    scale: 2,
    backgroundColor: '#ffffff',
    useCORS: true,
    logging: false,
  });

  const imgData = canvas.toDataURL('image/png');
  const pdf = new jsPDF('p', 'mm', 'a4');
  const pdfWidth = 210;
  const pdfHeight = (canvas.height * pdfWidth) / canvas.width;

  let heightLeft = pdfHeight;
  let position = 0;
  const pageHeight = 297;

  pdf.addImage(imgData, 'PNG', 0, position, pdfWidth, pdfHeight);
  heightLeft -= pageHeight;

  while (heightLeft > 0) {
    position = heightLeft - pdfHeight;
    pdf.addPage();
    pdf.addImage(imgData, 'PNG', 0, position, pdfWidth, pdfHeight);
    heightLeft -= pageHeight;
  }

  return pdf;
}

export async function exportElementAsPDF(
  element: HTMLElement,
  filename: string,
  popup?: Window | null,
) {
  const pdf = await buildPdf(element);
  const blob = pdf.output('blob') as Blob;
  downloadBlob(blob, filename, popup);
}

/**
 * Same rendering as `exportElementAsPDF` but returns the PDF as a base64 string
 * (no `data:` prefix) instead of triggering a download. Used for signing and
 * evidence export flows.
 */
export async function elementToPDFBase64(element: HTMLElement): Promise<string> {
  const pdf = await buildPdf(element);
  const ab = pdf.output('arraybuffer') as ArrayBuffer;
  const u8 = new Uint8Array(ab);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode(...u8.subarray(i, i + chunk));
  }
  return btoa(bin);
}

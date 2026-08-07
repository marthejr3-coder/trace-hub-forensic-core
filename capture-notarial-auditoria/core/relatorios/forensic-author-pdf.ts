/**
 * Helpers para desenhar identificação do autor (4 modos)
 * em relatórios gerados via jsPDF puro.
 */
import type jsPDF from 'jspdf';
import {
  type ForensicAuthor,
  MODE_BADGE,
  TITLE_BY_MODE,
  FILE_PREFIX_BY_MODE,
  getAuthorRows,
  getSignatureSubline,
  disclaimerForMode,
} from './forensic-author';

/** Sobrescreve o título de um laudo conforme o modo do autor. */
export function getReportTitle(author: ForensicAuthor | null | undefined, fallback: string): string {
  if (!author) return fallback;
  return TITLE_BY_MODE[author.mode];
}

/** Sobrescreve o prefixo do nome do arquivo conforme o modo do autor. */
export function getReportFilePrefix(author: ForensicAuthor | null | undefined, fallback: string): string {
  if (!author) return fallback;
  return FILE_PREFIX_BY_MODE[author.mode];
}

/**
 * Desenha o bloco "Identificação do Signatário Técnico" em jsPDF.
 * Retorna o próximo Y disponível.
 */
export function drawAuthorBlockPDF(
  pdf: jsPDF,
  author: ForensicAuthor,
  opts: { x: number; y: number; width: number },
): number {
  const { x, width } = opts;
  let y = opts.y;
  const padding = 3;
  const lineH = 4.5;

  const rows = getAuthorRows(author);
  const disclaimer = disclaimerForMode(author.mode);

  const headerH = 5;
  // estimativa de altura para o disclaimer (≈2 linhas)
  const disclaimerH = disclaimer ? 10 : 0;
  const boxH = headerH + padding + rows.length * lineH + padding + disclaimerH;

  pdf.setDrawColor(180, 180, 180);
  pdf.setFillColor(245, 247, 250);
  pdf.rect(x, y, width, boxH, 'FD');

  // Header
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(8);
  pdf.setTextColor(15, 76, 58);
  pdf.text(`IDENTIFICAÇÃO DO SIGNATÁRIO — ${MODE_BADGE[author.mode].toUpperCase()}`, x + padding, y + headerH);

  // Rows
  let ry = y + headerH + padding + 1;
  pdf.setFontSize(8);
  pdf.setTextColor(40, 40, 40);
  for (const [label, value] of rows) {
    pdf.setFont('helvetica', 'bold');
    pdf.text(`${label}:`, x + padding, ry);
    pdf.setFont('helvetica', 'normal');
    const valLines = pdf.splitTextToSize(value, width - padding * 2 - 45);
    pdf.text(valLines[0] || '', x + padding + 45, ry);
    ry += lineH;
  }

  if (disclaimer) {
    pdf.setFont('helvetica', 'italic');
    pdf.setFontSize(7);
    pdf.setTextColor(120, 80, 0);
    const disc = pdf.splitTextToSize(disclaimer, width - padding * 2);
    pdf.text(disc, x + padding, ry + 1);
  }

  pdf.setTextColor(0, 0, 0);
  return y + boxH + 4;
}

/**
 * Desenha a linha de assinatura ao fim do laudo (centralizada).
 * Retorna o próximo Y disponível.
 */
export function drawSignaturePDF(
  pdf: jsPDF,
  author: ForensicAuthor,
  opts: { pageWidth: number; y: number },
): number {
  let y = opts.y;
  const cx = opts.pageWidth / 2;
  const w = 100;
  pdf.setDrawColor(40, 40, 40);
  pdf.line(cx - w / 2, y, cx + w / 2, y);
  y += 4;
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(9);
  pdf.setTextColor(20, 20, 20);
  pdf.text(author.fullName || '________________________', cx, y, { align: 'center' });
  y += 4;
  pdf.setFont('helvetica', 'italic');
  pdf.setFontSize(8);
  pdf.setTextColor(80, 80, 80);
  pdf.text(getSignatureSubline(author) || MODE_BADGE[author.mode], cx, y, { align: 'center' });
  y += 4;
  if (author.localEmissao) {
    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(7);
    pdf.text(`${author.localEmissao} · ${new Date().toLocaleDateString('pt-BR')}`, cx, y, { align: 'center' });
    y += 4;
  }
  pdf.setTextColor(0, 0, 0);
  return y;
}

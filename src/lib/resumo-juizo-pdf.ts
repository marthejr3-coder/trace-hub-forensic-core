/**
 * "Resumo para o Juízo" — bloco em linguagem jurídica simples no topo
 * de todo laudo, conforme recomendação do laudo pericial Jun/2026.
 *
 * Traduz a robustez técnica (SHA-256 + OpenTimestamps + RFC 3161) em
 * 4 linhas que o magistrado entende sem precisar consultar o perito.
 */
import type jsPDF from 'jspdf';

export interface ResumoJuizoInput {
  /** O que foi coletado (ex.: "URL https://exemplo.com" ou "Arquivo nota.pdf") */
  objeto: string;
  /** Hash SHA-256 do conteúdo capturado */
  sha256: string;
  /** Data/hora ISO da coleta */
  capturadoEm: string;
  /** Responsável pela coleta (nome + identificador profissional, se houver) */
  responsavel?: string;
  /** IP do coletor, quando conhecido */
  ipColetor?: string;
  /** URL pública de verificação independente */
  verificacaoUrl?: string;
}

const FUNDAMENTO_LEGAL =
  'Fundamentos: CPP arts. 158-A a 158-F (cadeia de custódia, Lei 13.964/2019); ' +
  'Marco Civil art. 10-A; CPC art. 411, II; ISO/IEC 27037:2012.';

const O_QUE_PROVA =
  'O que isto prova: integridade do conteúdo (SHA-256 NIST FIPS 180-4) + ' +
  'data não-retroativa (OpenTimestamps/Bitcoin + RFC 3161 FreeTSA). ' +
  'O que NÃO prova: autoria do conteúdo original ou veracidade das afirmações nele contidas. ' +
  'NÃO é assinatura PAdES ICP-Brasil — é selo de integridade verificável por terceiros.';

/**
 * Desenha o bloco "Resumo para o Juízo" em jsPDF puro.
 * Retorna o próximo Y disponível.
 */
export function drawResumoJuizoPDF(
  pdf: jsPDF,
  input: ResumoJuizoInput,
  opts: { x: number; y: number; width: number },
): number {
  const { x, width } = opts;
  let y = opts.y;
  const padding = 4;
  const lineH = 4.2;

  // Linha 1: objeto + data
  const dataStr = (() => {
    try {
      const d = new Date(input.capturadoEm);
      return `${d.toLocaleString('pt-BR')} (UTC ${input.capturadoEm})`;
    } catch {
      return input.capturadoEm;
    }
  })();

  const linhas: Array<[string, string]> = [
    ['Objeto', input.objeto],
    ['Coletado em', dataStr],
    ['Responsável', `${input.responsavel || '—'}${input.ipColetor ? ` · IP ${input.ipColetor}` : ''}`],
    ['Hash SHA-256', input.sha256],
  ];

  // Estimativa de altura: header + 4 linhas + 2 blocos de texto longo (~4 linhas cada)
  const boxH = padding + 5 + linhas.length * lineH + 6 + 14 + 16 + padding;

  pdf.setDrawColor(16, 185, 129);
  pdf.setLineWidth(0.5);
  pdf.setFillColor(240, 253, 244);
  pdf.roundedRect(x, y, width, boxH, 2, 2, 'FD');

  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(9);
  pdf.setTextColor(6, 95, 70);
  pdf.text('RESUMO PARA O JUÍZO — leitura em 30 segundos', x + padding, y + padding + 3);

  let ry = y + padding + 8;
  pdf.setFontSize(8);
  for (const [label, valor] of linhas) {
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(40, 40, 40);
    pdf.text(`${label}:`, x + padding, ry);
    pdf.setFont(label === 'Hash SHA-256' ? 'courier' : 'helvetica', 'normal');
    pdf.setTextColor(20, 20, 20);
    const valLines = pdf.splitTextToSize(valor, width - padding * 2 - 30);
    pdf.text(valLines[0] || '', x + padding + 30, ry);
    ry += lineH;
    if (valLines.length > 1 && label === 'Hash SHA-256') {
      pdf.text(valLines[1], x + padding + 30, ry);
      ry += lineH;
    }
  }

  ry += 2;
  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(7.2);
  pdf.setTextColor(50, 50, 50);
  const provaLines = pdf.splitTextToSize(O_QUE_PROVA, width - padding * 2);
  pdf.text(provaLines, x + padding, ry);
  ry += provaLines.length * 3.4 + 1.5;

  pdf.setFont('helvetica', 'italic');
  pdf.setTextColor(80, 80, 80);
  const fundLines = pdf.splitTextToSize(FUNDAMENTO_LEGAL, width - padding * 2);
  pdf.text(fundLines, x + padding, ry);
  ry += fundLines.length * 3.4;

  if (input.verificacaoUrl) {
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(6, 95, 70);
    pdf.setFontSize(7);
    pdf.text(`Verifique em: ${input.verificacaoUrl}`, x + padding, ry + 1);
  }

  pdf.setTextColor(0, 0, 0);
  return y + boxH + 4;
}

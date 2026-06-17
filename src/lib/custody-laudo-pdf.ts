/**
 * Geração de Laudo de Cadeia de Custódia em PDF.
 * Reusa selo TraceHub via QR + registerForensicReport.
 */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import QRCode from 'qrcode';
import { registerForensicReport, getValidatorUrl } from '@/lib/forensic-seal';
import { openPopupForDownload } from '@/lib/ios-download';
import { downloadPdfWithSelfHash } from '@/lib/pdf-self-hash';
import { drawResumoJuizoPDF } from '@/lib/resumo-juizo-pdf';
import {
  type ForensicAuthor, TITLE_BY_MODE, FILE_PREFIX_BY_MODE,
  MODE_BADGE, AUTHOR_BLOCK_TITLE, getAuthorRows, getSignatureSubline,
  disclaimerForMode,
} from '@/lib/forensic-author';


export type LaudoMode = 'video' | 'image' | 'simple';

export interface CustodyFields {
  numeroProcesso?: string;
  tipoFonte?: string;
  descricaoDispositivo?: string;
  formaObtencao?: string;
  coletor?: string;
  cargoColetor?: string;
  dataHoraColeta?: string;
  suporteOriginal?: string;
  copiaForense?: string;
  hashColeta?: string;
  observacoes?: string;
}

export interface LaudoInput {
  mode: LaudoMode;
  fileName: string;
  fileSize: number;
  format: string;
  sha256: string;
  metadados: Array<[string, string]>;
  custody: CustodyFields;
  alertas?: string[];
  reportTypeLabel?: string;
  author?: ForensicAuthor;
}

const SUBTITLE_BY_MODE: Record<LaudoMode, string> = {
  video: 'Cadeia de Custódia de Prova Digital — Vídeo',
  image: 'Análise Forense de Imagem',
  simple: 'Cadeia de Custódia de Prova Digital',
};


const RODAPE =
  'Documento gerado pelo TraceHub para fins de documentação de cadeia de custódia de prova digital, conforme ISO/IEC 27037:2012, CPC art. 411, II e, por analogia, CPP art. 158-A (Lei 13.964/2019) e jurisprudência do STJ.';

const fmt = (n: number) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
};

const CUSTODY_LABELS: Record<keyof CustodyFields, string> = {
  numeroProcesso: 'Nº Processo / Inquérito',
  tipoFonte: 'Tipo de fonte',
  descricaoDispositivo: 'Descrição do dispositivo',
  formaObtencao: 'Forma de obtenção',
  coletor: 'Quem coletou',
  cargoColetor: 'Cargo do coletor',
  dataHoraColeta: 'Data/hora da coleta',
  suporteOriginal: 'Suporte original recebido',
  copiaForense: 'Cópia forense bit-a-bit',
  hashColeta: 'Hash gerado na coleta',
  observacoes: 'Observações',
};

export async function gerarLaudoCustodiaPDF(input: LaudoInput): Promise<void> {
  const popup = openPopupForDownload('Gerando documento forense…');

  const authorMode = input.author?.mode ?? 'perito';
  const tituloPrincipal = TITLE_BY_MODE[authorMode];
  const subtitulo = SUBTITLE_BY_MODE[input.mode];
  const filePrefix = FILE_PREFIX_BY_MODE[authorMode];

  // Registra na base central (não bloqueante)
  registerForensicReport({
    evidenceHash: input.sha256,
    reportType: input.mode === 'video' ? 'chain_of_custody' : 'metadata_decoder',
    subject: input.fileName,
    metadata: {
      file_size: input.fileSize,
      format: input.format,
      processo: input.custody.numeroProcesso,
      mode: input.mode,
      author_mode: authorMode,
      author_name: input.author?.fullName,
      author_registry: input.author?.registroProfissional || input.author?.matricula,
      document_number: input.author?.documentNumber,
    },
  });

  const doc = new jsPDF();
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();

  // Cabeçalho
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('TRACE HUB', 14, 14);
  doc.setFontSize(14);
  doc.text(tituloPrincipal, 14, 22);
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(9);
  doc.setTextColor(80);
  doc.text(subtitulo, 14, 27);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100);
  const hojeStr = `Gerado em ${new Date().toLocaleString('pt-BR')}`;
  const docNumStr = input.author?.documentNumber ? ` — Nº ${input.author.documentNumber}` : '';
  const localStr = input.author?.localEmissao ? ` — ${input.author.localEmissao}` : '';
  doc.text(`${hojeStr}${docNumStr}${localStr}`, 14, 32);
  doc.setTextColor(0);

  // Resumo para o Juízo — bloco em linguagem leiga no topo
  let cursorY = drawResumoJuizoPDF(
    doc,
    {
      objeto: `${input.fileName} (${input.format})`,
      sha256: input.sha256,
      capturadoEm: input.custody.dataHoraColeta || new Date().toISOString(),
      responsavel: input.author?.fullName || input.custody.coletor,
      verificacaoUrl: getValidatorUrl(input.sha256),
    },
    { x: 14, y: 38, width: pageW - 28 },
  );

  // Identificação do Autor (todos os modos)
  if (input.author) {
    const authorRows = getAuthorRows(input.author);
    autoTable(doc, {
      startY: cursorY,
      head: [[`Identificação do ${AUTHOR_BLOCK_TITLE[authorMode]}`, 'Valor']],
      body: authorRows,
      styles: { fontSize: 9, cellPadding: 2 },
      headStyles: { fillColor: [30, 30, 30] },
    });
    cursorY = (doc as any).lastAutoTable.finalY + 4;
  }



  // Identificação do arquivo
  autoTable(doc, {
    startY: cursorY,
    head: [['Identificação do arquivo', 'Valor']],
    body: [
      ['Nome', input.fileName],
      ['Tamanho', fmt(input.fileSize)],
      ['Formato', input.format],
      ['Nº processo / inquérito', input.custody.numeroProcesso || '—'],
    ],
    styles: { fontSize: 9, cellPadding: 2 },
    headStyles: { fillColor: [30, 30, 30] },
  });

  // Hash em destaque
  let y = (doc as any).lastAutoTable.finalY + 6;
  doc.setDrawColor(16, 185, 129);
  doc.setLineWidth(0.5);
  doc.roundedRect(14, y, pageW - 28, 18, 2, 2);
  doc.setFontSize(8);
  doc.setTextColor(6, 95, 70);
  doc.setFont('helvetica', 'bold');
  doc.text('HASH SHA-256 DO ARQUIVO', 18, y + 5);
  doc.setFont('courier', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(0);
  doc.text(input.sha256.slice(0, 64), 18, y + 11);
  if (input.sha256.length > 64) doc.text(input.sha256.slice(64), 18, y + 15);
  y += 22;

  // Metadados extraídos
  if (input.metadados.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [['Metadado extraído', 'Valor']],
      body: input.metadados.map(([k, v]) => [k, String(v).slice(0, 200)]),
      styles: { fontSize: 8, cellPadding: 2 },
      headStyles: { fillColor: [30, 30, 30] },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  } else {
    autoTable(doc, {
      startY: y,
      head: [['Metadados']],
      body: [['Nenhum metadado estruturado foi extraído deste arquivo.']],
      styles: { fontSize: 9, cellPadding: 3, textColor: [120, 60, 30] },
      headStyles: { fillColor: [30, 30, 30] },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Cadeia de custódia
  const custodyRows = (Object.keys(CUSTODY_LABELS) as Array<keyof CustodyFields>)
    .map(k => [CUSTODY_LABELS[k], (input.custody[k] || '—').toString()]);
  autoTable(doc, {
    startY: y,
    head: [['Cadeia de Custódia', 'Valor']],
    body: custodyRows,
    styles: { fontSize: 9, cellPadding: 2 },
    headStyles: { fillColor: [30, 30, 30] },
  });
  y = (doc as any).lastAutoTable.finalY + 4;

  // Alertas
  if (input.alertas && input.alertas.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [['Alertas Forenses']],
      body: input.alertas.map(a => [a]),
      styles: { fontSize: 8, cellPadding: 3, textColor: [180, 60, 30] },
      headStyles: { fillColor: [180, 60, 30], textColor: [255, 255, 255] },
    });
    y = (doc as any).lastAutoTable.finalY + 4;
  }

  // Disclaimer condicional por modo (policial / operador_direito / vitima)
  const disclaimerText = disclaimerForMode(authorMode);
  if (disclaimerText) {
    const isVitima = authorMode === 'vitima';
    // estima altura — vítima tem texto maior e merece destaque mais forte
    const boxH = isVitima ? 22 : 16;
    if (y > pageH - boxH - 10) { doc.addPage(); y = 20; }
    // cores por severidade
    const fill: [number, number, number] = isVitima ? [255, 240, 240] : [255, 248, 230];
    const stroke: [number, number, number] = isVitima ? [200, 60, 60] : [180, 120, 30];
    const headColor: [number, number, number] = isVitima ? [160, 30, 30] : [120, 70, 10];
    const headLabel = authorMode === 'policial' ? 'NOTA OPERACIONAL'
      : authorMode === 'operador_direito' ? 'NATUREZA DO DOCUMENTO'
      : 'ATENÇÃO — RELATO DA VÍTIMA';
    doc.setDrawColor(...stroke);
    doc.setFillColor(...fill);
    doc.roundedRect(14, y, pageW - 28, boxH, 2, 2, 'FD');
    doc.setFont('helvetica', 'bolditalic');
    doc.setFontSize(8);
    doc.setTextColor(...headColor);
    doc.text(headLabel, 18, y + 5);
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(7.5);
    doc.text(disclaimerText, 18, y + 10, { maxWidth: pageW - 36 } as any);
    doc.setTextColor(0);
    y += boxH + 4;
  }

  // Assinatura
  if (input.author && input.author.fullName) {
    if (y > pageH - 50) { doc.addPage(); y = 20; }
    y += 8;
    doc.setDrawColor(60);
    doc.setLineWidth(0.3);
    doc.line(pageW / 2 - 50, y, pageW / 2 + 50, y);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0);
    doc.text(input.author.fullName, pageW / 2, y + 5, { align: 'center' } as any);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(80);
    const idLine = getSignatureSubline(input.author);
    if (idLine) doc.text(idLine, pageW / 2, y + 10, { align: 'center' } as any);
    doc.text(MODE_BADGE[authorMode], pageW / 2, y + 14, { align: 'center' } as any);
    doc.setTextColor(0);
    y += 18;
  }



  // Selo TraceHub + QR
  try {
    const validatorUrl = getValidatorUrl(input.sha256);
    const qrDataUrl = await QRCode.toDataURL(validatorUrl, { errorCorrectionLevel: 'M', margin: 1, width: 200 });
    const sealTop = y + 4 > pageH - 70 ? (doc.addPage(), 20) : y + 4;
    doc.setDrawColor(16, 185, 129);
    doc.setLineWidth(0.6);
    doc.roundedRect(14, sealTop, pageW - 28, 56, 2, 2);
    doc.setFontSize(10);
    doc.setTextColor(6, 95, 70);
    doc.setFont('helvetica', 'bold');
    doc.text('SELO DE AUTENTICIDADE — TRACE HUB', 18, sealTop + 7);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(60);
    doc.text(`Tipo: ${input.reportTypeLabel || subtitulo} (${MODE_BADGE[authorMode]})`, 18, sealTop + 13);
    doc.text('Verifique escaneando o QR ao lado ou em trace-hub.com/verificar-evidencia', 18, sealTop + 36);
    doc.addImage(qrDataUrl, 'PNG', pageW - 46, sealTop + 8, 30, 30);
    doc.setFontSize(6);
    doc.setTextColor(100);
    doc.text('Escaneie p/ validar', pageW - 46, sealTop + 42);
  } catch (err) {
    console.warn('[laudo-pdf] selo falhou', err);
  }

  // Rodapé fixo
  doc.setFontSize(7);
  doc.setTextColor(80);
  doc.text(RODAPE, 14, pageH - 8, { maxWidth: pageW - 28 } as any);

  const slug = input.fileName.replace(/\W+/g, '_').slice(0, 60);
  const pdfFilename = `${filePrefix}_${slug}_${Date.now()}.pdf`;
  await downloadPdfWithSelfHash(doc.output('blob') as Blob, pdfFilename, popup);
}


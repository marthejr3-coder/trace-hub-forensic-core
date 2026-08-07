/**
 * Certidão de Ancoragem Temporal — PDF curto emitido para Atas Notariais
 * antigas cujo payload completo não foi persistido (registros anteriores à
 * gravação de `metadata.result`).
 *
 * A certidão NÃO substitui a ata: ela certifica exclusivamente o que é
 * verificável de forma independente — o código único (SHA-256) da evidência,
 * a data do registro e o estado da ancoragem OpenTimestamps/Bitcoin.
 */
import type jsPDF from 'jspdf';
import { createPdf } from '@/lib/jspdf-safe';

export interface CertidaoAncoragemInput {
  evidenceHash: string;
  subject?: string | null;
  originalUrl?: string | null;
  finalUrl?: string | null;
  createdAt: string;
  stamp?: {
    status?: string | null;
    ots_base64?: string | null;
    ots_sha256?: string | null;
    bitcoin_block_height?: number | null;
    block_hash?: string | null;
    block_time?: number | string | null;
    ots_confirmed_at?: string | null;
    created_at?: string | null;
    calendars?: string[] | null;
  } | null;
  operatorName?: string | null;
  operatorEmail?: string | null;
}

const MARGIN = 18;

function cleanText(s: string): string {
  return String(s ?? '').replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"').replace(/[\u2013\u2014]/g, '-');
}

function fmtDate(v?: string | number | null): string {
  if (!v) return 'Nao informado';
  try {
    const d = typeof v === 'number' ? new Date(v * 1000) : new Date(v);
    if (Number.isNaN(d.getTime())) return String(v);
    return d.toLocaleString('pt-BR');
  } catch {
    return String(v);
  }
}

export function buildCertidaoAncoragemPDF(input: CertidaoAncoragemInput): jsPDF {
  const pdf = createPdf({ unit: 'mm', format: 'a4' });
  const W = pdf.internal.pageSize.getWidth();
  let y = 22;

  const line = (text: string, size = 10, style: 'normal' | 'bold' | 'italic' = 'normal', gap = 5.5) => {
    pdf.setFont('helvetica', style);
    pdf.setFontSize(size);
    const wrapped = pdf.splitTextToSize(cleanText(text), W - MARGIN * 2);
    pdf.text(wrapped, MARGIN, y);
    y += wrapped.length * (size * 0.42) + gap - 2;
  };

  const kv = (label: string, value: string) => {
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(9);
    pdf.text(cleanText(label), MARGIN, y);
    pdf.setFont('helvetica', 'normal');
    const wrapped = pdf.splitTextToSize(cleanText(value || 'Nao informado'), W - MARGIN * 2 - 52);
    pdf.text(wrapped, MARGIN + 52, y);
    y += Math.max(wrapped.length * 4.2, 4.2) + 2.2;
  };

  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(15);
  pdf.text('CERTIDAO DE ANCORAGEM TEMPORAL', W / 2, y, { align: 'center' });
  y += 7;
  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(9);
  pdf.text('Documento complementar a Ata Notarial Digital', W / 2, y, { align: 'center' });
  y += 10;

  pdf.setDrawColor(15, 76, 58);
  pdf.setLineWidth(0.6);
  pdf.line(MARGIN, y, W - MARGIN, y);
  y += 8;

  line(
    'Certifica-se que o codigo unico abaixo foi registrado na plataforma Trace Hub na data indicada ' +
      'e submetido a ancoragem temporal independente. Esta certidao atesta exclusivamente a existencia ' +
      'e a anterioridade do codigo unico; o conteudo integral da captura consta da ata notarial ' +
      'originalmente emitida.',
    9.5,
  );
  y += 2;

  line('1. Identificacao do registro', 11, 'bold', 4);
  kv('Objeto', input.subject || input.finalUrl || input.originalUrl || 'Nao informado');
  kv('URL solicitada', input.originalUrl || 'Nao informado');
  kv('URL final', input.finalUrl || 'Nao informado');
  kv('Registrado em', fmtDate(input.createdAt));
  kv('Operador', input.operatorName || input.operatorEmail || 'Nao informado');
  y += 3;

  line('2. Codigo unico da evidencia (SHA-256)', 11, 'bold', 4);
  pdf.setFont('courier', 'normal');
  pdf.setFontSize(9);
  const hashLines = pdf.splitTextToSize(input.evidenceHash.toLowerCase(), W - MARGIN * 2);
  pdf.text(hashLines, MARGIN, y);
  y += hashLines.length * 4.6 + 5;

  const st = input.stamp;
  const confirmed = !!(st && st.status === 'confirmed_bitcoin' && st.bitcoin_block_height);
  line('3. Ancoragem OpenTimestamps / Bitcoin', 11, 'bold', 4);
  kv('Situacao', confirmed ? 'CONFIRMADA em bloco Bitcoin' : st?.ots_base64 ? 'Ancorada — aguardando confirmacao em bloco Bitcoin' : 'Sem selo emitido');
  kv('Selo emitido em', fmtDate(st?.created_at ?? null));
  kv('Bloco Bitcoin', confirmed ? `#${st?.bitcoin_block_height}` : 'Nao informado');
  kv('Hash do bloco', confirmed ? String(st?.block_hash ?? 'Nao informado') : 'Nao informado');
  kv('Data do bloco', confirmed ? fmtDate(st?.block_time ?? null) : 'Nao informado');
  kv('Confirmado em', confirmed ? fmtDate(st?.ots_confirmed_at ?? null) : 'Nao informado');
  if (st?.ots_sha256) kv('SHA-256 do arquivo .ots', st.ots_sha256);
  if (confirmed) {
    kv('Explorador', `https://mempool.space/block/${st?.block_hash ?? st?.bitcoin_block_height}`);
  }
  y += 3;

  line('4. Como verificar de forma independente', 11, 'bold', 4);
  line(
    '1) Baixe o arquivo .ots correspondente na plataforma. 2) Instale o cliente oficial OpenTimestamps ' +
      '(pip install opentimestamps-client). 3) Execute: ots verify --digest ' +
      input.evidenceHash.toLowerCase() +
      ' evidencia.ots. 4) Confira o bloco retornado no explorador publico mempool.space.',
    9.5,
  );
  y += 2;

  line('5. Limites desta certidao', 11, 'bold', 4);
  line(
    'Esta certidao nao reproduz o conteudo capturado nem substitui a ata notarial digital original. ' +
      'Ela comprova apenas que o codigo unico existia na data da ancoragem, sendo impossivel sua ' +
      'pre-datacao. Emitida por sistema automatizado, sem intervencao manual sobre os valores acima.',
    9.5,
  );

  y = pdf.internal.pageSize.getHeight() - 16;
  pdf.setFont('helvetica', 'italic');
  pdf.setFontSize(8);
  pdf.text(
    cleanText(`Trace Hub — emitida em ${new Date().toLocaleString('pt-BR')} · CPC art. 411, II · MP 2.200-2/2001`),
    W / 2,
    y,
    { align: 'center' },
  );

  return pdf;
}

export function downloadCertidaoAncoragem(input: CertidaoAncoragemInput): void {
  const pdf = buildCertidaoAncoragemPDF(input);
  pdf.save(`certidao-ancoragem-${input.evidenceHash.slice(0, 12)}.pdf`);
}

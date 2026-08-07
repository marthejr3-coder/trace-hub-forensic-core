/**
 * forensic-report-ui.ts
 * =====================
 * Componentes visuais reutilizáveis (jsPDF) da identidade forense do Trace Hub:
 * resumo executivo, fluxogramas, quadros de garantias, cartões de princípios,
 * caixa de confiabilidade e status da ancoragem.
 *
 * Regras rígidas:
 *  • Nenhum valor técnico é calculado aqui — apenas apresentação.
 *  • Somente glifos Latin-1 (fontes built-in do jsPDF são WinAnsi/CP1252):
 *    marcadores ASCII [OK] / [ ] / [..] e setas desenhadas com linhas.
 *  • Toda função devolve o próximo `y` disponível e trata quebra de página.
 */

import {
  CUSTODY_BLOCK_TITLE,
  buildCustodyBlockRows,
  resolveCustodyStatus,
  type CustodyBlockInput,
} from '@/lib/forensic-custody-block';

import {
  PLATFORM_PROVENANCE_NOTE,
  PLATFORM_PROVENANCE_TITLE,
  buildPlatformProvenanceRows,
  getPlatformProvenanceSync,
  type PlatformProvenance,
} from '@/lib/platform-provenance';


import {
  ANCHORING_STATUS_TITLE,
  BLOCKCHAIN_EXPLANATION,
  EXEC_SUMMARY_NOTE,
  EXEC_SUMMARY_TITLE,
  EXHIBITOR_RESPONSIBILITY_TEXT,
  EXHIBITOR_RESPONSIBILITY_TITLE,
  INDEPENDENT_VERIFICATION_INTRO,
  INSTITUTIONAL_INTRO,
  METHODOLOGY_FLOW_STEPS,
  STJ_COMPLIANCE_PARAGRAPHS,
  STJ_COMPLIANCE_TITLE,
  TIME_REFERENCE_NOTE,
  buildAnchoringStatusLines,
  buildExecSummaryItems,
  formatDualTime,
  type AnchoringStatusInfo,
  type ExecStatus,
  type ExecSummaryFlags,
} from '@/lib/forensic-report-copy';

// ─── Paleta e métricas ────────────────────────────────────────────────────────

export const RC = {
  primary: [15, 76, 58] as [number, number, number],
  accent: [30, 41, 59] as [number, number, number],
  soft: [241, 245, 249] as [number, number, number],
  softGreen: [240, 247, 243] as [number, number, number],
  border: [148, 163, 184] as [number, number, number],
  text: [25, 25, 25] as [number, number, number],
  muted: [100, 100, 100] as [number, number, number],
  amber: [180, 83, 9] as [number, number, number],
};

export const SECTION_GAP = 10;
export const BLOCK_GAP = 6;

export interface PdfCtx {
  /** Instância jsPDF. */
  pdf: any;
  y: number;
  marginX: number;
  contentW: number;
  pageW: number;
  pageH: number;
  marginTop: number;
  marginBottom?: number;
  /** Fonte base do laudo ("times" na Ata Notarial, "helvetica" nos demais). */
  font?: string;
  /** Chamado quando uma página nova é criada (para o contador do chamador). */
  onAddPage?: () => void;
}

function sanitize(text?: string | null): string {
  return (text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\u00A0/g, ' ')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
    .replace(/[\u201C\u201D\u201E\u201F]/g, '"')
    .replace(/\u2026/g, '...')
    .replace(/[\u2192\u2794\u2193]/g, '->')
    .replace(/[^\x00-\xFF]/g, '?');
}

function fnt(ctx: PdfCtx): string {
  return ctx.font || 'helvetica';
}

/** Garante espaço vertical; cria página quando necessário. Devolve y atualizado. */
export function ensureSpace(ctx: PdfCtx, y: number, need: number): number {
  const bottom = ctx.pageH - (ctx.marginBottom ?? 18);
  if (y + need > bottom) {
    ctx.pdf.addPage();
    ctx.onAddPage?.();
    return ctx.marginTop;
  }
  return y;
}

function paragraph(
  ctx: PdfCtx,
  y: number,
  text: string,
  opts: { size?: number; italic?: boolean; bold?: boolean; color?: [number, number, number]; lineH?: number; x?: number; width?: number } = {},
): number {
  const { pdf } = ctx;
  pdf.setFont(fnt(ctx), opts.italic ? 'italic' : opts.bold ? 'bold' : 'normal');
  pdf.setFontSize(opts.size ?? 9.5);
  pdf.setTextColor(...(opts.color ?? RC.text));
  const width = opts.width ?? ctx.contentW;
  const lines: string[] = pdf.splitTextToSize(sanitize(text), width);
  const lh = opts.lineH ?? 4.6;
  let cur = ensureSpace(ctx, y, lines.length * lh + 2);
  pdf.text(lines, opts.x ?? ctx.marginX, cur);
  return cur + lines.length * lh + 2;
}

function sectionTitle(ctx: PdfCtx, y: number, title: string): number {
  const { pdf } = ctx;
  let cur = ensureSpace(ctx, y, 14);
  pdf.setFont(fnt(ctx), 'bold');
  pdf.setFontSize(11);
  pdf.setTextColor(...RC.primary);
  pdf.text(sanitize(title).toUpperCase(), ctx.marginX, cur);
  cur += 2.2;
  pdf.setDrawColor(...RC.primary);
  pdf.setLineWidth(0.5);
  pdf.line(ctx.marginX, cur, ctx.marginX + ctx.contentW, cur);
  return cur + 5;
}

function statusMark(status: ExecStatus): string {
  return status === 'ok' ? '[OK]' : status === 'pending' ? '[..]' : '[ - ]';
}

function statusColor(status: ExecStatus): [number, number, number] {
  return status === 'ok' ? RC.primary : status === 'pending' ? RC.amber : RC.muted;
}

// ─── 7. Resumo Executivo ──────────────────────────────────────────────────────

export interface ExecutiveSummaryOptions extends ExecSummaryFlags {
  /** Linhas de identificação exibidas no topo (rótulo, valor). */
  identity?: [string, string][];
  /** Não abrir nova página (usa a posição corrente). */
  inline?: boolean;
}

export function drawExecutiveSummary(ctx: PdfCtx, opts: ExecutiveSummaryOptions): number {
  const { pdf } = ctx;
  if (!opts.inline) {
    pdf.addPage();
    ctx.onAddPage?.();
  }
  let y = opts.inline ? ctx.y : ctx.marginTop;

  // Faixa de título
  y = ensureSpace(ctx, y, 20);
  pdf.setFillColor(...RC.primary);
  pdf.rect(ctx.marginX, y - 5, ctx.contentW, 11, 'F');
  pdf.setFont(fnt(ctx), 'bold');
  pdf.setFontSize(13);
  pdf.setTextColor(255, 255, 255);
  pdf.text(sanitize(EXEC_SUMMARY_TITLE).toUpperCase(), ctx.marginX + 3, y + 2.5);
  y += 12;

  if (opts.identity?.length) {
    pdf.setFontSize(8.5);
    for (const [label, value] of opts.identity) {
      y = ensureSpace(ctx, y, 6);
      pdf.setFont(fnt(ctx), 'bold');
      pdf.setTextColor(...RC.accent);
      pdf.text(sanitize(label) + ':', ctx.marginX, y);
      pdf.setFont(fnt(ctx), 'normal');
      pdf.setTextColor(...RC.text);
      const lines: string[] = pdf.splitTextToSize(sanitize(value), ctx.contentW - 42);
      pdf.text(lines, ctx.marginX + 42, y);
      y += lines.length * 4.2 + 1.2;
    }
    y += 3;
  }

  // Indicadores em duas colunas
  const items = buildExecSummaryItems(opts);
  const colW = ctx.contentW / 2 - 2;
  const rowH = 9;
  const rows = Math.ceil(items.length / 2);
  y = ensureSpace(ctx, y, rows * rowH + 6);
  items.forEach((item, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = ctx.marginX + col * (colW + 4);
    const by = y + row * rowH;
    pdf.setFillColor(...(item.status === 'ok' ? RC.softGreen : RC.soft));
    pdf.setDrawColor(...RC.border);
    pdf.setLineWidth(0.2);
    pdf.rect(x, by, colW, rowH - 1.5, 'FD');
    pdf.setFont('courier', 'bold');
    pdf.setFontSize(8);
    pdf.setTextColor(...statusColor(item.status));
    pdf.text(statusMark(item.status), x + 2, by + 5.4);
    pdf.setFont(fnt(ctx), 'bold');
    pdf.setFontSize(8.6);
    pdf.setTextColor(...RC.accent);
    pdf.text(sanitize(item.label), x + 14, by + 5.4);
  });
  y += rows * rowH + 4;

  y = paragraph(ctx, y, EXEC_SUMMARY_NOTE, { size: 8.5, italic: true, color: RC.muted });
  return y;
}

// ─── 4. Introdução institucional ──────────────────────────────────────────────

export function drawInstitutionalIntro(ctx: PdfCtx, y: number): number {
  const { pdf } = ctx;
  const text = sanitize(INSTITUTIONAL_INTRO);
  pdf.setFont(fnt(ctx), 'normal');
  pdf.setFontSize(9.3);
  const lines: string[] = pdf.splitTextToSize(text, ctx.contentW - 10);
  const boxH = lines.length * 4.5 + 12;
  let cur = ensureSpace(ctx, y, boxH + 4);
  pdf.setFillColor(...RC.softGreen);
  pdf.setDrawColor(...RC.primary);
  pdf.setLineWidth(0.3);
  pdf.rect(ctx.marginX, cur, ctx.contentW, boxH, 'FD');
  // Barra lateral de destaque
  pdf.setFillColor(...RC.primary);
  pdf.rect(ctx.marginX, cur, 1.8, boxH, 'F');
  pdf.setFont(fnt(ctx), 'bold');
  pdf.setFontSize(8.5);
  pdf.setTextColor(...RC.primary);
  pdf.text('APRESENTACAO INSTITUCIONAL', ctx.marginX + 5, cur + 5.5);
  pdf.setFont(fnt(ctx), 'normal');
  pdf.setFontSize(9.3);
  pdf.setTextColor(...RC.text);
  pdf.text(lines, ctx.marginX + 5, cur + 11);
  return cur + boxH + BLOCK_GAP;
}

// ─── 1. Fluxograma da metodologia ─────────────────────────────────────────────

export function drawMethodologyFlowchart(ctx: PdfCtx, y: number, steps: string[] = METHODOLOGY_FLOW_STEPS): number {
  const { pdf } = ctx;
  let cur = sectionTitle(ctx, y, 'Fluxo da Evidência');

  const boxW = Math.min(112, ctx.contentW - 24);
  const boxH = 8.2;
  const gap = 4.4;
  const x = ctx.marginX + (ctx.contentW - boxW) / 2;

  steps.forEach((step, i) => {
    cur = ensureSpace(ctx, cur, boxH + gap + 4);
    // Caixa
    pdf.setFillColor(...(i === steps.length - 1 ? RC.primary : RC.soft));
    pdf.setDrawColor(...(i === steps.length - 1 ? RC.primary : RC.border));
    pdf.setLineWidth(0.25);
    pdf.rect(x, cur, boxW, boxH, 'FD');
    // Indicador de etapa
    pdf.setFillColor(...(i === steps.length - 1 ? [255, 255, 255] as [number, number, number] : RC.primary));
    pdf.rect(x, cur, 6.4, boxH, 'F');
    pdf.setFont('courier', 'bold');
    pdf.setFontSize(7);
    pdf.setTextColor(...(i === steps.length - 1 ? RC.primary : [255, 255, 255] as [number, number, number]));
    pdf.text(String(i + 1).padStart(2, '0'), x + 1.1, cur + 5.4);
    // Rótulo
    pdf.setFont(fnt(ctx), i === steps.length - 1 ? 'bold' : 'normal');
    pdf.setFontSize(8.6);
    pdf.setTextColor(...(i === steps.length - 1 ? [255, 255, 255] as [number, number, number] : RC.accent));
    pdf.text(sanitize(step), x + 9, cur + 5.4);
    cur += boxH;
    // Conector com seta
    if (i < steps.length - 1) {
      const cx = x + boxW / 2;
      pdf.setDrawColor(...RC.primary);
      pdf.setLineWidth(0.5);
      pdf.line(cx, cur, cx, cur + gap - 1.4);
      pdf.setFillColor(...RC.primary);
      pdf.triangle(cx - 1.3, cur + gap - 1.6, cx + 1.3, cur + gap - 1.6, cx, cur + gap, 'F');
      cur += gap;
    }
  });

  return cur + BLOCK_GAP;
}

// Blocos removidos por decisão editorial (metodologia enxuta):
// quadro de garantias, cartões de princípios, arquitetura em camadas e caixa
// "Por que esta evidência é confiável?" — o conteúdo essencial permanece no
// Resumo Executivo, no fluxograma e na seção de metodologia.



// ─── 13. Status da ancoragem ──────────────────────────────────────────────────

export interface AnchoringStatusBoxOptions extends AnchoringStatusInfo {
  /** Comandos públicos de verificação (exibidos quando confirmado). */
  verificationCommands?: string[];
}

export function drawAnchoringStatus(ctx: PdfCtx, y: number, info: AnchoringStatusBoxOptions): number {
  const { pdf } = ctx;
  let cur = sectionTitle(ctx, y, ANCHORING_STATUS_TITLE);

  const lines = buildAnchoringStatusLines(info);
  const rowH = 7.4;
  cur = ensureSpace(ctx, cur, lines.length * rowH + 6);
  lines.forEach((item, i) => {
    const by = cur + i * rowH;
    pdf.setFillColor(...(item.status === 'ok' ? RC.softGreen : item.status === 'pending' ? [254, 249, 235] as [number, number, number] : RC.soft));
    pdf.setDrawColor(...RC.border);
    pdf.setLineWidth(0.2);
    pdf.rect(ctx.marginX, by, ctx.contentW, rowH - 1.2, 'FD');
    pdf.setFont('courier', 'bold');
    pdf.setFontSize(8);
    pdf.setTextColor(...statusColor(item.status));
    pdf.text(statusMark(item.status), ctx.marginX + 2.5, by + 4.6);
    pdf.setFont(fnt(ctx), item.status === 'ok' ? 'bold' : 'normal');
    pdf.setFontSize(8.6);
    pdf.setTextColor(...RC.accent);
    pdf.text(sanitize(item.label), ctx.marginX + 16, by + 4.6);
  });
  cur += lines.length * rowH + 3;

  if (info.bitcoinBlockHeight) {
    const rows: [string, string][] = [
      ['Bloco Bitcoin', `#${info.bitcoinBlockHeight}`],
      ['Block hash', info.blockHash || 'Não informado'],
      ['Horário do bloco', formatDualTime(info.blockTimeUtc)],
    ];
    cur = ensureSpace(ctx, cur, rows.length * 6 + 4);
    rows.forEach(([label, value]) => {
      pdf.setFont(fnt(ctx), 'bold');
      pdf.setFontSize(8.2);
      pdf.setTextColor(...RC.primary);
      pdf.text(sanitize(label) + ':', ctx.marginX + 2, cur);
      const isHash = /^[0-9a-fA-F]{32,}$/.test(value.replace(/\s/g, ''));
      pdf.setFont(isHash ? 'courier' : fnt(ctx), 'normal');
      pdf.setFontSize(isHash ? 7.2 : 8.2);
      pdf.setTextColor(...RC.text);
      const vLines: string[] = pdf.splitTextToSize(sanitize(value), ctx.contentW - 40);
      pdf.text(vLines, ctx.marginX + 38, cur);
      cur += vLines.length * 4 + 2;
    });
    if (info.verificationCommands?.length) {
      cur = paragraph(ctx, cur + 1, 'Comandos públicos de verificação:', { size: 8.2, bold: true, color: RC.primary });
      pdf.setFont('courier', 'normal');
      pdf.setFontSize(7);
      pdf.setTextColor(...RC.text);
      for (const cmd of info.verificationCommands) {
        const cLines: string[] = pdf.splitTextToSize(sanitize(cmd), ctx.contentW - 6);
        cur = ensureSpace(ctx, cur, cLines.length * 3.6 + 2);
        pdf.setFont('courier', 'normal');
        pdf.setFontSize(7);
        pdf.text(cLines, ctx.marginX + 3, cur);
        cur += cLines.length * 3.6 + 1.6;
      }
    }
  } else {
    cur = paragraph(
      ctx,
      cur,
      'A ancoragem em Blockchain Bitcoin encontra-se pendente de confirmação da rede no momento da ' +
        'emissão deste relatório. O artefato .ots acompanha o material e permite a qualquer terceiro ' +
        'confirmar posteriormente o bloco e a data de inclusão, sem intervenção do Trace Hub.',
      { size: 8.4, italic: true, color: RC.amber },
    );
  }

  return cur + BLOCK_GAP - 3;
}

// ─── 5 / 10 / 11 / 12 / 14 — Notas didáticas ──────────────────────────────────

export function drawIndependentVerificationNote(ctx: PdfCtx, y: number): number {
  return infoBox(ctx, y, 'Verificação independente', [INDEPENDENT_VERIFICATION_INTRO]);
}

export function drawTimeReferenceNote(ctx: PdfCtx, y: number): number {
  return infoBox(ctx, y, 'Referência de horário (UTC x horário local)', [TIME_REFERENCE_NOTE]);
}

export function drawBlockchainExplanation(ctx: PdfCtx, y: number): number {
  return infoBox(ctx, y, 'Esclarecimento sobre a Blockchain Bitcoin', [BLOCKCHAIN_EXPLANATION], RC.amber);
}

/** Conformidade técnica com a jurisprudência do STJ. */
export function drawStjCompliance(ctx: PdfCtx, y: number): number {
  return infoBox(ctx, y, STJ_COMPLIANCE_TITLE, STJ_COMPLIANCE_PARAGRAPHS, RC.accent);
}

/** Responsabilização do exibidor da prova. */
export function drawExhibitorResponsibility(ctx: PdfCtx, y: number): number {
  return infoBox(ctx, y, EXHIBITOR_RESPONSIBILITY_TITLE, [EXHIBITOR_RESPONSIBILITY_TEXT], RC.accent);
}

/** Caixa informativa genérica com título em faixa fina. */
export function infoBox(
  ctx: PdfCtx,
  y: number,
  title: string,
  paragraphs: string[],
  accent: [number, number, number] = RC.primary,
): number {
  const { pdf } = ctx;
  pdf.setFont(fnt(ctx), 'normal');
  pdf.setFontSize(8.6);
  const wrapped = paragraphs.map((p) => pdf.splitTextToSize(sanitize(p), ctx.contentW - 10) as string[]);
  const bodyH = wrapped.reduce((a, w) => a + w.length * 4.1, 0) + 2.4 * (wrapped.length - 1);
  const boxH = bodyH + 12;
  let cur = ensureSpace(ctx, y, Math.min(boxH, ctx.pageH - ctx.marginTop - 20) + 4);

  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(...accent);
  pdf.setLineWidth(0.4);
  pdf.rect(ctx.marginX, cur, ctx.contentW, boxH, 'FD');
  pdf.setFillColor(...accent);
  pdf.rect(ctx.marginX, cur, ctx.contentW, 6.6, 'F');
  pdf.setFont(fnt(ctx), 'bold');
  pdf.setFontSize(8.6);
  pdf.setTextColor(255, 255, 255);
  pdf.text(sanitize(title).toUpperCase(), ctx.marginX + 3, cur + 4.6);

  let ty = cur + 11;
  wrapped.forEach((lines) => {
    pdf.setFont(fnt(ctx), 'normal');
    pdf.setFontSize(8.6);
    pdf.setTextColor(...RC.text);
    pdf.text(lines, ctx.marginX + 5, ty);
    ty += lines.length * 4.1 + 2.4;
  });

  return cur + boxH + BLOCK_GAP;
}

// ─── Cadeia de custódia da sessão (bloco padrão) ──────────────────────────────

export function drawCustodyBlock(ctx: PdfCtx, y: number, input: CustodyBlockInput): number {
  const { pdf } = ctx;
  const rows = buildCustodyBlockRows(input);
  const st = resolveCustodyStatus(input);
  if (!rows.length && !st.note) return y;

  let cur = sectionTitle(ctx, y, CUSTODY_BLOCK_TITLE);
  const labelW = 42;

  rows.forEach(([label, value]) => {
    const isHash = /SHA-256\s+[0-9a-fA-F]{32,}/.test(value);
    pdf.setFont(isHash ? 'courier' : fnt(ctx), 'normal');
    pdf.setFontSize(isHash ? 7.2 : 8.4);
    const vLines: string[] = pdf.splitTextToSize(sanitize(value), ctx.contentW - labelW - 4);
    cur = ensureSpace(ctx, cur, vLines.length * 4.2 + 3);
    pdf.setFont(fnt(ctx), 'bold');
    pdf.setFontSize(8.4);
    pdf.setTextColor(...RC.accent);
    pdf.text(sanitize(label) + ':', ctx.marginX + 1, cur);
    pdf.setFont(isHash ? 'courier' : fnt(ctx), 'normal');
    pdf.setFontSize(isHash ? 7.2 : 8.4);
    pdf.setTextColor(...RC.text);
    pdf.text(vLines, ctx.marginX + labelW, cur);
    cur += vLines.length * (isHash ? 3.8 : 4.2) + 2;
  });

  // Faixa de status
  const accent = st.status === 'verificada' ? RC.primary : st.status === 'ressalvas' ? RC.amber : RC.muted;
  cur = ensureSpace(ctx, cur + 1.5, 12);
  pdf.setFillColor(...accent);
  pdf.rect(ctx.marginX, cur, ctx.contentW, 8.4, 'F');
  pdf.setFont('courier', 'bold');
  pdf.setFontSize(8);
  pdf.setTextColor(255, 255, 255);
  pdf.text(st.status === 'verificada' ? '[OK]' : st.status === 'ressalvas' ? '[..]' : '[ - ]', ctx.marginX + 2.5, cur + 5.6);
  pdf.setFont(fnt(ctx), 'bold');
  pdf.setFontSize(9.2);
  pdf.text('STATUS: ' + sanitize(st.label), ctx.marginX + 16, cur + 5.6);
  cur += 10.4;

  if (st.note) {
    cur = paragraph(ctx, cur, st.note, { size: 8.2, italic: true, color: RC.muted });
  }

  return cur + BLOCK_GAP - 2;
}

// ─── Procedência da plataforma (build/binário) ────────────────────────────────

export function drawPlatformProvenance(
  ctx: PdfCtx,
  y: number,
  prov?: PlatformProvenance,
): number {
  const { pdf } = ctx;
  const provenance = prov ?? getPlatformProvenanceSync();
  const rows = buildPlatformProvenanceRows(provenance);
  if (!rows.length) return y;

  let cur = sectionTitle(ctx, y, PLATFORM_PROVENANCE_TITLE);
  const labelW = 62;

  rows.forEach(([label, value]) => {
    const mono = /^[0-9a-fA-F]{32,}$/.test(value.trim());
    pdf.setFont(mono ? 'courier' : fnt(ctx), 'normal');
    pdf.setFontSize(mono ? 7.2 : 8.4);
    const vLines: string[] = pdf.splitTextToSize(sanitize(value), ctx.contentW - labelW - 4);
    cur = ensureSpace(ctx, cur, vLines.length * 4.2 + 3);
    pdf.setFont(fnt(ctx), 'bold');
    pdf.setFontSize(8.4);
    pdf.setTextColor(...RC.accent);
    const lLines: string[] = pdf.splitTextToSize(sanitize(label) + ':', labelW - 2);
    pdf.text(lLines, ctx.marginX + 1, cur);
    pdf.setFont(mono ? 'courier' : fnt(ctx), 'normal');
    pdf.setFontSize(mono ? 7.2 : 8.4);
    pdf.setTextColor(...RC.text);
    pdf.text(vLines, ctx.marginX + labelW, cur);
    cur += Math.max(vLines.length, lLines.length) * (mono ? 3.8 : 4.2) + 2;
  });

  cur = paragraph(ctx, cur + 1, PLATFORM_PROVENANCE_NOTE, { size: 8.2, italic: true, color: RC.muted });
  return cur + BLOCK_GAP - 2;
}


// ─── 6. Barra de selos técnicos (capa) ────────────────────────────────────────


export function drawTrustBadges(
  ctx: PdfCtx,
  y: number,
  badges: string[] = ['ISO/IEC 27037:2012', 'FIPS 180-4', 'RFC 3161', 'OpenTimestamps', 'Bitcoin'],
): number {
  const { pdf } = ctx;
  let cur = ensureSpace(ctx, y, 12);
  const gap = 2.2;
  pdf.setFont(fnt(ctx), 'bold');
  pdf.setFontSize(7);
  const widths = badges.map((b) => pdf.getTextWidth(sanitize(b)) + 6);
  const total = widths.reduce((a, w) => a + w, 0) + gap * (badges.length - 1);
  let x = ctx.marginX + Math.max(0, (ctx.contentW - total) / 2);
  badges.forEach((b, i) => {
    pdf.setFillColor(...RC.softGreen);
    pdf.setDrawColor(...RC.primary);
    pdf.setLineWidth(0.2);
    pdf.rect(x, cur, widths[i], 6, 'FD');
    pdf.setTextColor(...RC.primary);
    pdf.setFont(fnt(ctx), 'bold');
    pdf.setFontSize(7);
    pdf.text(sanitize(b), x + 3, cur + 4);
    x += widths[i] + gap;
  });
  return cur + 6 + BLOCK_GAP;
}

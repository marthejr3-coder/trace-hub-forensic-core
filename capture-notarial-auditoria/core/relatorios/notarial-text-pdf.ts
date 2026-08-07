/**
 * notarial-text-pdf.ts
 *
 * Renderizador 100% textual (jsPDF nativo) para a Ata Notarial Digital.
 * Substitui o fluxo html2canvas anterior — nenhuma rasterização do DOM.
 *
 * Únicas chamadas pdf.addImage permitidas:
 *   (a) brasão/logo no topo          ← ShieldCheck renderizado em canvas off-screen
 *   (b) screenshot no Anexo Único    ← result.screenshot_base64
 *   (c) QR de validação na Parte IV  ← gerado via qrcode lib
 *
 * API pública mantida:
 *   exportTextualNotarialPDF(input, filename, popupWindow) → { blob, base64 }
 *   textualNotarialPDFToBase64(input) → string
 */

import { getJsPDF } from '@/lib/jspdf-safe';
import { downloadBlob } from "@/lib/ios-download";
import { detectSocialNetwork } from "@/lib/social-network-detect";
import type { DnsIntegrity, NetworkMetadata } from "@/lib/evidence-network";
import { buildIso27037PdfRows } from "@/lib/iso27037-verification-block";
import { buildMethodologyRows, METHODOLOGY_TITLE } from "@/lib/forensic-methodology";
import { formatDualTime } from "@/lib/forensic-report-copy";
import {
  drawAnchoringStatus,
  drawCustodyBlock,

  drawBlockchainExplanation,
  drawExecutiveSummary,
  drawExhibitorResponsibility,
  drawIndependentVerificationNote,
  drawInstitutionalIntro,
  drawMethodologyFlowchart,
  drawStjCompliance,
  drawTimeReferenceNote,
  drawTrustBadges,
  type PdfCtx,
} from "@/lib/forensic-report-ui";
import { drawPlatformProvenance } from "@/lib/forensic-report-ui";
import { drawSignaturePDF } from "@/lib/forensic-author-pdf";
import type { AuthorMode } from "@/lib/forensic-author";
import { loadPlatformProvenance } from "@/lib/platform-provenance";



// ─── Tipos ────────────────────────────────────────────────────────────────────

type DohResult = {
  records: string[];
  status: 'ok' | 'nxdomain' | 'error' | string;
  raw_excerpt?: string;
};

type OfflineEvidence = {
  reason: string;
  http_status?: number | null;
  http_error_message?: string | null;
  dns?: { cloudflare?: DohResult; google?: DohResult };
  dns_consensus?: 'offline' | 'partial' | 'online';
  wayback?: { available: boolean; closest_url?: string; closest_timestamp?: string };
  probed_at?: string;
};

type NotarialPdfResult = {
  original_url: string;
  final_url: string;
  timestamp: string;
  timestamp_source: string;
  http_status: number;
  http_headers?: Record<string, string>;
  page_title?: string;
  page_description?: string;
  screenshot_base64: string | null;
  screenshot_mime: string | null;
  screenshot_hash: string | null;
  screenshot_warning?: string | null;
  html_hash: string;
  html_size: number;
  html_truncated?: boolean;
  html_full_size?: number;
  operator_ip?: string;
  request_id?: string;
  evidence_hash: string;
  evidence_hash_sha512?: string | null;
  dnsIntegrity?: DnsIntegrity | null;
  networkMetadata?: NetworkMetadata | null;
  site_status?: 'online' | 'offline' | 'partial';
  offline_summary?: string | null;
  offline_evidence?: OfflineEvidence | null;
  wayback_suggestion?: { url: string; timestamp: string } | null;
};

function humanizeOfflineReason(reason?: string | null): string {
  switch (reason) {
    case 'dns_nxdomain':
      return 'Domínio não existe nos servidores DNS públicos (NXDOMAIN) — o endereço foi removido da internet ou nunca foi registrado.';
    case 'connection_refused':
      return 'O servidor recusou ativamente a conexão na porta consultada.';
    case 'timeout':
      return 'O servidor não respondeu dentro do tempo limite (timeout).';
    case 'tls_error':
      return 'Falha na negociação TLS/HTTPS — certificado inválido, expirado ou indisponível.';
    case 'http_error':
      return 'O servidor respondeu com erro de aplicação (HTTP 4xx/5xx).';
    case 'dns_error':
      return 'Erro técnico ao consultar os servidores DNS públicos.';
    default:
      return reason ? `Motivo registrado: ${reason}` : 'Servidor não respondeu à consulta.';
  }
}

type StampLike = {
  timestamp_id: string;
  date_created: string;
  currencies?: string[];
  rfc3161_timestamp: string | null;
  submitted_at: string;
  bitcoin_block_height?: number | null;
  ots_confirmed_at?: string | null;
  verified_at?: string | null;
  status?: string | null;
  ots_sha256?: string | null;
  block_hash?: string | null;
  block_merkle_root?: string | null;
  block_time?: string | null;
  calendars?: string[];
  ots_filename?: string;
} | null;

type SealedLike = {
  session_id: string;
  ended_at: string;
  merkle_root: string;
  event_count: number;
  originstamp_id: string | null;
  bitcoin_block_height?: number | null;
  ots_confirmed_at?: string | null;
  verified_at?: string | null;
  status?: string | null;
  ots_sha256?: string | null;
  block_hash?: string | null;
  block_merkle_root?: string | null;
  block_time?: string | null;
  calendars?: string[];
  video_path?: string | null;
  video_signed_url?: string | null;
  video_sha256?: string | null;
  video_size?: number | null;
  video_mime?: string | null;
  video_duration_seconds?: number | null;
  video_bucket?: string | null;
  video_signed_url_expires_at?: string | null;
  target_url?: string | null;
} | null;

export interface NotarialTextPdfInput {
  result: NotarialPdfResult;
  requester?: {
    name?: string;
    cpf?: string | null;
    cargo?: string | null;
    email?: string;
    submittedAt?: string;
  } | null;
  author?: {
    mode?: string;
    name?: string;
    cpf?: string | null;
    registry?: string | null;
    title?: string | null;
  } | null;
  stamp?: StampLike;
  sealedResult?: SealedLike;
}

// ─── Constantes de layout ─────────────────────────────────────────────────────

const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN_X = 18;
const MARGIN_TOP = 26;
const MARGIN_BOTTOM = 20;
const CONTENT_W = PAGE_W - MARGIN_X * 2;
const VALIDATOR_BASE = "https://www.trace-hub.com/verificar-evidencia";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function asDate(value?: string | null) {
  if (!value) return "Nao informado";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString("pt-BR");
}

function formatBytes(value?: number | null) {
  if (!value || value <= 0) return "Nao informado";
  if (value < 1024) return `${value.toLocaleString("pt-BR")} bytes`;
  if (value < 1024 * 1024) return `${(value / 1024).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} KB`;
  return `${(value / 1024 / 1024).toLocaleString("pt-BR", { maximumFractionDigits: 2 })} MB`;
}

function formatHashForDisplay(hash?: string | null): string {
  if (!hash) return "Nao informado";
  const groups: string[] = [];
  for (let i = 0; i < hash.length; i += 8) groups.push(hash.slice(i, i + 8));
  return groups.join(" ");
}

function cleanText(text?: string | null) {
  return (
    (text || "")
      .replace(/\s+/g, " ")
      .replace(/[^\S\r\n]+/g, " ")
      .trim()
      // Normaliza NBSP e afins
      .replace(/\u00A0/g, " ")
      // Mapeia pontuação Unicode comum para equivalentes suportados pelo WinAnsi/CP1252
      // (a fonte built-in Times/Helvetica do jsPDF suporta esses code points diretamente,
      // mas garantimos consistência mesmo em ambientes com quirks de encoding)
      .replace(/[\u2013\u2014]/g, "-")        // en-dash / em-dash → hífen
      .replace(/[\u2018\u2019\u201A\u201B]/g, "'") // aspas curvas simples
      .replace(/[\u201C\u201D\u201E\u201F]/g, '"') // aspas curvas duplas
      .replace(/\u2026/g, "...")               // ellipsis
      .replace(/[\u2192\u2794]/g, "->")        // setas
      // Preserva Latin-1 completo (acentuação PT-BR: á é í ó ú â ê ô ã õ ç à etc.)
      // Remove apenas emojis / scripts não-latinos (CJK, árabe, etc.)
      .replace(/[^\x00-\xFF]/g, "?")
  );
}

function postCodeFromUrl(rawUrl: string) {
  try {
    const u = new URL(rawUrl);
    const parts = u.pathname.split("/").filter(Boolean);
    const idx = parts.findIndex((p) => ["p", "reel", "reels", "tv", "status", "video"].includes(p.toLowerCase()));
    if (idx >= 0 && parts[idx + 1]) return parts[idx + 1];
    return parts[parts.length - 1] || null;
  } catch {
    return null;
  }
}

function arrayBufferToBase64(ab: ArrayBuffer) {
  const u8 = new Uint8Array(ab);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode(...u8.subarray(i, i + chunk));
  }
  return btoa(bin);
}

/** Renders a tiny ShieldCheck-like logo onto an off-screen canvas → PNG dataURL */
async function buildLogoDataUrl(): Promise<string> {
  const size = 64;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;
  // Shield background
  ctx.fillStyle = "#0F4C3A";
  ctx.beginPath();
  ctx.moveTo(size / 2, 4);
  ctx.lineTo(size - 8, 14);
  ctx.lineTo(size - 8, size / 2);
  ctx.quadraticCurveTo(size - 8, size - 8, size / 2, size - 4);
  ctx.quadraticCurveTo(8, size - 8, 8, size / 2);
  ctx.lineTo(8, 14);
  ctx.closePath();
  ctx.fill();
  // Check mark
  ctx.strokeStyle = "#FFFFFF";
  ctx.lineWidth = 5;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.beginPath();
  ctx.moveTo(18, size / 2);
  ctx.lineTo(28, size / 2 + 10);
  ctx.lineTo(46, size / 2 - 10);
  ctx.stroke();
  return canvas.toDataURL("image/png");
}

/** Generates a QR code dataURL for the given URL */
async function buildQrDataUrl(url: string): Promise<string | null> {
  try {
    const QRCode = (await import("qrcode")).default;
    return await QRCode.toDataURL(url, { width: 180, margin: 1, color: { dark: "#0F4C3A" } });
  } catch {
    return null;
  }
}

// ─── Builder ──────────────────────────────────────────────────────────────────

async function buildTextualNotarialPDF(input: NotarialTextPdfInput) {
  const provenance = await loadPlatformProvenance();
  const jsPDF = getJsPDF();

  const pdf = new jsPDF("p", "mm", "a4");

  const result = input.result;
  const social = detectSocialNetwork(result.final_url || result.original_url);
  const postCode = postCodeFromUrl(result.final_url || result.original_url);
  const subjectUrl = result.final_url || result.original_url;
  const generatedAt = new Date();
  const verifyUrl = `${VALIDATOR_BASE}?hash=${result.evidence_hash}`;
  const shortHash = result.evidence_hash.slice(0, 16);

  // Pre-build assets (run in parallel)
  const [logoDataUrl, qrDataUrl] = await Promise.all([buildLogoDataUrl(), buildQrDataUrl(verifyUrl)]);

  let y = MARGIN_TOP;
  let page = 1;

  // ── Layout helpers ──────────────────────────────────────────────────────────

  const ensure = (needed: number) => {
    if (y + needed <= PAGE_H - MARGIN_BOTTOM) return;
    pdf.addPage();
    page += 1;
    y = MARGIN_TOP;
  };

  const setBody = () => {
    pdf.setFont("times", "normal");
    pdf.setFontSize(10.5);
    pdf.setTextColor(30, 30, 30);
  };

  /** Single text block with word-wrap, auto page-break */
  const textBlock = (
    value: string,
    opts: {
      size?: number;
      bold?: boolean;
      italic?: boolean;
      color?: [number, number, number];
      indent?: number;
      lineH?: number;
    } = {},
  ) => {
    setBody();
    const style = opts.italic ? "italic" : opts.bold ? "bold" : "normal";
    pdf.setFont("times", style);
    pdf.setFontSize(opts.size ?? 10.5);
    if (opts.color) pdf.setTextColor(...opts.color);
    else pdf.setTextColor(30, 30, 30);
    const x = MARGIN_X + (opts.indent ?? 0);
    const width = CONTENT_W - (opts.indent ?? 0);
    const lines = pdf.splitTextToSize(cleanText(value), width);
    const lh = opts.lineH ?? 5.0;
    ensure(lines.length * lh + 2);
    pdf.text(lines, x, y);
    y += lines.length * lh + 2;
  };

  /** Section heading with coloured rule */
  const heading = (title: string, level: 1 | 2 = 1) => {
    ensure(14);
    if (y > MARGIN_TOP + 2) y += level === 1 ? 5 : 3;
    if (level === 1) {
      pdf.setFont("times", "bold");
      pdf.setFontSize(12);
      pdf.setTextColor(15, 76, 58);
      pdf.text(cleanText(title).toUpperCase(), MARGIN_X, y);
      y += 2.5;
      pdf.setDrawColor(15, 76, 58);
      pdf.setLineWidth(0.5);
      pdf.line(MARGIN_X, y, PAGE_W - MARGIN_X, y);
      y += 5.5;
    } else {
      pdf.setFont("times", "bold");
      pdf.setFontSize(10.5);
      pdf.setTextColor(15, 76, 58);
      pdf.text(cleanText(title), MARGIN_X, y);
      y += 2;
      pdf.setDrawColor(15, 76, 58);
      pdf.setLineWidth(0.25);
      pdf.line(MARGIN_X, y, MARGIN_X + CONTENT_W * 0.5, y);
      y += 4.5;
    }
  };

  /** Part separator (Parte I, II, III…) */
  const partHeader = (number: string, title: string, subtitle: string) => {
    ensure(20);
    y += 4;
    pdf.setDrawColor(15, 76, 58);
    pdf.setLineWidth(0.8);
    pdf.line(MARGIN_X, y, PAGE_W - MARGIN_X, y);
    y += 4;
    pdf.setFont("times", "bold");
    pdf.setFontSize(8.5);
    pdf.setTextColor(15, 76, 58);
    pdf.text(`PARTE ${number}`, MARGIN_X, y);
    y += 5;
    pdf.setFont("times", "bold");
    pdf.setFontSize(13);
    pdf.setTextColor(26, 26, 26);
    pdf.text(cleanText(title).toUpperCase(), MARGIN_X, y);
    y += 5;
    pdf.setFont("times", "italic");
    pdf.setFontSize(9.5);
    pdf.setTextColor(90, 90, 90);
    const subLines = pdf.splitTextToSize(cleanText(subtitle), CONTENT_W);
    pdf.text(subLines, MARGIN_X, y);
    y += subLines.length * 4.5 + 2;
    pdf.setDrawColor(15, 76, 58);
    pdf.setLineWidth(0.5);
    pdf.line(MARGIN_X, y, PAGE_W - MARGIN_X, y);
    y += 1;
    pdf.setLineWidth(0.2);
    pdf.line(MARGIN_X, y, PAGE_W - MARGIN_X, y);
    y += 6;
  };

  /** Two-column key/value table row */
  const kv = (rows: Array<[string, string | number | null | undefined]>, labelW = 52) => {
    setBody();
    rows.forEach(([label, value]) => {
      const rawLabel = String(label ?? "");
      // Cabeçalhos de seção (ex.: "--- AUDITABILIDADE ---") vêm com valor vazio intencionalmente.
      // Não substituir por "Não informado" — renderiza-se apenas o rótulo, sem placeholder órfão.
      const isSectionDivider = rawLabel.startsWith("---") || rawLabel.startsWith("═") || rawLabel.startsWith("—");
      const isEmpty = value == null || value === "";
      // Se rótulo tem valor vazio E não é divisor, ainda renderiza "Não informado" (compat).
      // Mas se for divisor, renderiza célula única sem placeholder.
      const val = isEmpty ? (isSectionDivider ? "" : "Não informado") : String(value);
      const safeLabel = cleanText(rawLabel);
      const safeVal = cleanText(val);
      const labelLines = pdf.splitTextToSize(safeLabel, labelW - 4);
      const valueLines = pdf.splitTextToSize(safeVal, CONTENT_W - labelW - 4);
      const rowH = Math.max(labelLines.length, valueLines.length) * 4.5 + 4;
      ensure(rowH + 2);
      pdf.setFillColor(245, 248, 246);
      pdf.rect(MARGIN_X, y - 3.5, CONTENT_W, rowH, "F");
      pdf.setDrawColor(210, 220, 216);
      pdf.setLineWidth(0.2);
      pdf.rect(MARGIN_X, y - 3.5, CONTENT_W, rowH);
      // Vertical divider
      pdf.line(MARGIN_X + labelW, y - 3.5, MARGIN_X + labelW, y - 3.5 + rowH);
      pdf.setFont("times", "bold");
      pdf.setFontSize(9);
      pdf.setTextColor(15, 76, 58);
      pdf.text(labelLines, MARGIN_X + 2, y);
      const isHash = safeVal.length > 32 && /^[0-9a-fA-F\s]+$/.test(safeVal.replace(/\s/g, ""));
      pdf.setFont(isHash ? "courier" : "times", "normal");
      pdf.setFontSize(isHash ? 7.8 : 9);
      pdf.setTextColor(25, 25, 25);
      pdf.text(valueLines, MARGIN_X + labelW + 2, y);
      y += rowH + 1.5;
    });
    y += 2;
  };

  /** Compact note line */
  const note = (value: string) => textBlock(value, { size: 8.5, italic: true, color: [100, 100, 100] });

  // ── PDF Metadata ────────────────────────────────────────────────────────────

  pdf.setProperties({
    title: "Ata Notarial Digital - Trace Hub",
    subject: subjectUrl,
    creator: "Trace Hub",
    keywords: "ata notarial, prova digital, hash, timestamp, evidencia digital",
  } as any);

  // ════════════════════════════════════════════════════════════════════════════
  // FRONTISPICIO
  // ════════════════════════════════════════════════════════════════════════════

  // Logo
  try {
    pdf.addImage(logoDataUrl, "PNG", PAGE_W / 2 - 10, y - 5, 20, 20);
    y += 18;
  } catch {
    y += 4;
  }

  pdf.setFont("times", "bold");
  pdf.setFontSize(8.5);
  pdf.setTextColor(100, 100, 100);
  pdf.text("TRACE HUB - PLATAFORMA DE EVIDENCIAS DIGITAIS", PAGE_W / 2, y, { align: "center" });
  y += 5;

  pdf.setDrawColor(15, 76, 58);
  pdf.setLineWidth(0.6);
  pdf.line(MARGIN_X, y, PAGE_W - MARGIN_X, y);
  y += 7;

  pdf.setFont("times", "bold");
  pdf.setFontSize(16);
  pdf.setTextColor(15, 76, 58);
  pdf.text("RELATORIO TECNICO FORENSE DE PROVA DIGITAL", PAGE_W / 2, y, { align: "center" });
  y += 7;
  pdf.setFontSize(14);
  const isOffline = result.site_status === 'offline';
  pdf.text(isOffline ? "ATA NOTARIAL DIGITAL DE INDISPONIBILIDADE" : "ATA NOTARIAL DIGITAL", PAGE_W / 2, y, { align: "center" });
  y += 5;

  pdf.setFont("times", "normal");
  pdf.setFontSize(9);
  pdf.setTextColor(80, 80, 80);
  pdf.text(`Emitida em: ${generatedAt.toLocaleString("pt-BR")}  |  Evidencia: ${shortHash}...`, PAGE_W / 2, y, {
    align: "center",
  });
  y += 8;

  textBlock(
    "Vem esta plataforma apresentar relatorio tecnico das diligencias digitais realizadas para " +
      "preservacao de conteudo publicado na internet, com foco em prova digital, cadeia de " +
      "custodia, hash criptografico e registro temporal independente, nos termos do art. 411, II " +
      "do CPC, do Provimento CNJ 100/2020 e da norma ISO/IEC 27037:2012.",
    { size: 10 },
  );

  y += 2;

  textBlock(
    "A prova digital nativa de internet (screenshots, HTML, headers HTTP) nao e vestigio material " +
      "nos termos do art. 158-A do CPP, mas evidencia documental eletronica regida pelo CPC art. 422 " +
      "e pela ISO/IEC 27037:2012. O presente laudo adota os principios da norma ISO como framework " +
      "tecnico primario e referencia o CPP 158-A apenas por analogia doutrinaria consolidada " +
      "(STJ, HC 1.036.370).",
    { size: 9, italic: true, color: [90, 90, 90] },
  );

  y += 2;

  textBlock(
    "LIMITES: Este relatorio atesta integridade do arquivo desde a captura e implementa toda a " +
      "cadeia de custodia, nao a autenticidade do conteudo original — como autenticacao cartorial " +
      "atesta a copia, nao o documento-fonte.",
    { size: 9, bold: true, color: [120, 53, 15] },
  );

  y += 3;

  // Tabela-resumo do frontispicio
  const offlineEv = result.offline_evidence || null;
  const offlineReasonText = humanizeOfflineReason(offlineEv?.reason);
  if (isOffline) {
    kv([
      ["URL consultada", subjectUrl],
      ["Timestamp", `${asDate(result.timestamp)} (${result.timestamp_source})`],
      ["Status do site no momento da coleta", "FORA DO AR - servidor nao respondeu"],
      ["Motivo tecnico", offlineReasonText],
      ["SHA-256 da evidencia", formatHashForDisplay(result.evidence_hash)],
      ["SHA-512 espelho", formatHashForDisplay(result.evidence_hash_sha512)],
    ]);
  } else {
    kv([
      ["URL capturada", subjectUrl],
      ["Timestamp", `${asDate(result.timestamp)} (${result.timestamp_source})`],
      ["Status HTTP", result.http_status],
      ["Titulo da pagina", result.page_title || "Nao informado"],
      ["SHA-256 da evidencia", formatHashForDisplay(result.evidence_hash)],
      ["SHA-512 espelho", formatHashForDisplay(result.evidence_hash_sha512)],
    ]);
  }


  // Bloco solicitante
  heading("1.0 Identificacao do Solicitante");
  if (input.requester?.name || input.requester?.cpf) {
    kv([
      ["Nome / Razao Social", input.requester?.name],
      ["CPF / CNPJ", input.requester?.cpf],
      ["Cargo / Funcao", input.requester?.cargo],
      ["E-mail", input.requester?.email],
      ["Data de solicitacao", asDate(input.requester?.submittedAt)],
    ]);
  } else {
    kv([
      ["Solicitante", input.author?.name || "Operador autenticado na plataforma Trace Hub"],
      ["Elaborado por", input.author?.title || input.author?.name || "Trace Hub - sistema automatizado"],
      ["Registro / OAB", input.author?.registry],
      ["CPF do signatario", input.author?.cpf],
    ]);
  }

  // Selo AUTENTICADO
  y += 3;
  pdf.setFont("times", "bold");
  pdf.setFontSize(11);
  pdf.setTextColor(15, 76, 58);
  pdf.setDrawColor(15, 76, 58);
  pdf.setLineWidth(0.4);
  pdf.rect(MARGIN_X, y - 5, CONTENT_W, 12);
  pdf.text("[AUTENTICADO] - Documento gerado por sistema tecnico homologado Trace Hub", PAGE_W / 2, y, {
    align: "center",
  });
  y += 12;

  // ════════════════════════════════════════════════════════════════════════════
  // RESUMO EXECUTIVO + METODOLOGIA TECNICA — assinatura tecnica do Trace Hub
  // (logo apos a identificacao, antes da primeira evidencia)
  // ════════════════════════════════════════════════════════════════════════════

  const btcHeight = input.stamp?.bitcoin_block_height || input.sealedResult?.bitcoin_block_height || null;
  const rc: PdfCtx = {
    pdf,
    y,
    marginX: MARGIN_X,
    contentW: CONTENT_W,
    pageW: PAGE_W,
    pageH: PAGE_H,
    marginTop: MARGIN_TOP,
    marginBottom: MARGIN_BOTTOM,
    font: "times",
    onAddPage: () => {
      page += 1;
    },
  };
  const syncRc = () => {
    rc.y = y;
  };

  // Selos técnicos da capa
  syncRc();
  y = drawTrustBadges(rc, y);

  // Resumo executivo (página própria, legível por magistrados)
  syncRc();
  y = drawExecutiveSummary(rc, {
    identity: [
      ["URL / Objeto", subjectUrl],
      ["SHA-256 da evidência", result.evidence_hash],
      ["Emissão do relatório", formatDualTime(generatedAt)],
      ["Coleta", formatDualTime(result.timestamp)],
    ],
    integrity: true,
    custody: true,
    clientServerMatch: "na",
    rfc3161: input.stamp?.rfc3161_timestamp ? "ok" : "na",
    bitcoin: btcHeight ? "ok" : "pending",
    originalsPreserved: true,
    metadata: true,
    auditable: true,
    iso27037: true,
  });

  // Cadeia de custódia da sessão (bloco padrão)
  {
    const anchors: string[] = [];
    if (input.stamp?.rfc3161_timestamp) anchors.push("RFC 3161 (FreeTSA)");
    if (input.stamp) anchors.push("OpenTimestamps / OriginStamp multi-chain");
    y = drawCustodyBlock(rc, y, {
      sessionId: input.sealedResult?.session_id || result.request_id || null,
      startedAt: result.timestamp,
      finishedAt: input.sealedResult?.ended_at || generatedAt,
      operatorName: input.author?.name || input.requester?.name || null,
      operatorEmail: input.requester?.email || null,
      authorMode: input.author?.mode || null,
      artifactCount: input.sealedResult?.event_count ?? null,
      masterHash: input.sealedResult?.merkle_root || result.evidence_hash,
      masterHashValid: true,
      chainIntact: true,
      anchors,
      anchorConfirmed: !!btcHeight,
      bitcoinBlockHeight: btcHeight,
    });
  }

  y = drawPlatformProvenance(rc, y, provenance);


  // Introdução institucional
  y = drawInstitutionalIntro(rc, y);


  heading(METHODOLOGY_TITLE);

  const methodologyRows = buildMethodologyRows({
    acquisitionMode: "assistida",
    hasSha512: !!result.evidence_hash_sha512,
    anchors: {
      rfc3161: !!input.stamp?.rfc3161_timestamp,
      opentimestamps: !!input.stamp,
      bitcoinConfirmed: !!btcHeight,
    },
    preservedArtifacts: {
      html: !isOffline,
      screenshot: !isOffline,
      video: !!input.sealedResult?.video_path,
      httpHeaders: !isOffline,
      dns: true,
      rdap: true,
      tls: !isOffline,
    },
  });

  // 1. Objetivo -> fluxograma -> itens 3-10
  kv(methodologyRows.slice(0, 2));
  y = drawMethodologyFlowchart(rc, y);
  kv(methodologyRows.slice(2));

  // Conformidade jurisprudencial e status de ancoragem
  y = drawStjCompliance(rc, y);
  y = drawExhibitorResponsibility(rc, y);
  y = drawAnchoringStatus(rc, y, {
    sha256: true,
    sha512: !!result.evidence_hash_sha512,
    clientServer: false,
    custody: true,
    rfc3161: !!input.stamp?.rfc3161_timestamp,
    opentimestamps: !!input.stamp,
    bitcoinBlockHeight: btcHeight,
    blockHash: input.stamp?.block_hash || input.sealedResult?.block_hash || null,
    blockTimeUtc: input.stamp?.block_time || input.sealedResult?.block_time || null,
  });
  y = drawIndependentVerificationNote(rc, y);
  y = drawTimeReferenceNote(rc, y);
  y = drawBlockchainExplanation(rc, y);




  // ════════════════════════════════════════════════════════════════════════════
  // AVISO — Site fora do ar (somente quando offline)
  // ════════════════════════════════════════════════════════════════════════════

  if (isOffline) {
    y += 4;
    ensure(70);
    const boxTop = y - 4;
    const boxX = MARGIN_X;
    const boxW = CONTENT_W;
    // Cabeçalho âmbar
    pdf.setFillColor(255, 244, 229);
    pdf.setDrawColor(194, 65, 12);
    pdf.setLineWidth(0.6);
    pdf.rect(boxX, boxTop, boxW, 9, "FD");
    pdf.setFont("times", "bold");
    pdf.setFontSize(11);
    pdf.setTextColor(154, 52, 18);
    pdf.text("AVISO - SITE FORA DO AR NO MOMENTO DA COLETA", PAGE_W / 2, boxTop + 6, { align: "center" });
    y = boxTop + 9 + 3;

    const probedAt = offlineEv?.probed_at ? new Date(offlineEv.probed_at).toLocaleString("pt-BR") : asDate(result.timestamp);
    const cf = offlineEv?.dns?.cloudflare?.status?.toUpperCase() || "sem resposta";
    const gg = offlineEv?.dns?.google?.status?.toUpperCase() || "sem resposta";

    textBlock(
      `O endereço ${subjectUrl} foi consultado em ${probedAt} em dois servidores DNS públicos independentes ` +
        `(Cloudflare 1.1.1.1: ${cf}; Google 8.8.8.8: ${gg}) e não foi possível obter qualquer resposta válida. ` +
        offlineReasonText,
      { size: 10.5 },
    );

    textBlock(
      "Por essa razão, NENHUMA captura visual (screenshot) ou conteúdo HTML foi gerado — não havia o que registrar. " +
        "Esta Ata documenta tecnicamente o fato jurídico da indisponibilidade, com fé pública técnica equivalente " +
        "à constatação prevista no art. 405, §1º do CPC.",
      { size: 10.5 },
    );

    const wb = result.wayback_suggestion || (offlineEv?.wayback?.available
      ? { url: offlineEv.wayback.closest_url || "", timestamp: offlineEv.wayback.closest_timestamp || "" }
      : null);
    if (wb && wb.url) {
      const wbDate = wb.timestamp && wb.timestamp.length >= 8
        ? `${wb.timestamp.slice(6, 8)}/${wb.timestamp.slice(4, 6)}/${wb.timestamp.slice(0, 4)}`
        : wb.timestamp;
      textBlock(
        `Existe registro histórico do site no Wayback Machine (Internet Archive), capturado em ${wbDate}. ` +
          "Recomenda-se gerar uma segunda Ata Notarial sobre o snapshot histórico para reconstituir o conteúdo " +
          "que estava no ar antes da remoção:",
        { size: 10.5 },
      );
      pdf.setFont("times", "normal");
      pdf.setFontSize(9);
      pdf.setTextColor(0, 0, 200);
      const wbLines = pdf.splitTextToSize(wb.url, CONTENT_W);
      ensure(wbLines.length * 4.5 + 2);
      pdf.textWithLink(wbLines[0], MARGIN_X, y, { url: wb.url });
      if (wbLines.length > 1) pdf.text(wbLines.slice(1), MARGIN_X, y + 4.5);
      y += wbLines.length * 4.5 + 3;
      pdf.setTextColor(30, 30, 30);
    }

    // Moldura inferior fechando o bloco
    pdf.setDrawColor(194, 65, 12);
    pdf.setLineWidth(0.4);
    pdf.line(MARGIN_X, y, PAGE_W - MARGIN_X, y);
    y += 4;
  }



  // ════════════════════════════════════════════════════════════════════════════
  // SELO PREMIUM — Captura em Ambiente Lacrado (condicional)
  // ════════════════════════════════════════════════════════════════════════════

  if (input.sealedResult) {
    const sr = input.sealedResult;
    pdf.addPage();
    page += 1;
    y = MARGIN_TOP;

    heading("SELO PREMIUM - Captura em Ambiente Lacrado");
    textBlock(
      "A presente evidencia foi produzida em sessao gravada e lacrada criptograficamente, com " +
        "registro de eventos de navegacao, ancoragem em blockchain (Bitcoin) e carimbo RFC 3161. " +
        "A integridade da sessao e verificavel pelo Merkle root abaixo.",
      { size: 10 },
    );
    y += 2;

    // Correção crítica: só declaramos "CONFIRMADO na blockchain Bitcoin" quando existe
    // um bloco Bitcoin real associado (block_height). Antes disso, mesmo com status
    // "confirmed_*" retornado pelo agregador OTS ou com ots_confirmed_at preenchido,
    // não há prova de inclusão em bloco minerado — o .ots está apenas no calendário.
    // Mesma lógica usada no Capture Link (Async OTS: RFC 3161 imediato + OTS assíncrono).
    const srBtcAnchored = !!sr.bitcoin_block_height;
    const srConfirmedAt = srBtcAnchored ? (sr.ots_confirmed_at || sr.verified_at || null) : null;
    const srExplorer = srBtcAnchored
      ? `https://mempool.space/block/${sr.bitcoin_block_height}`
      : "https://mempool.space (aguardando agregação em bloco Bitcoin — tipicamente 1-6h)";
    const srSubmittedAt = (sr as any).submitted_at || (sr as any).ots_submitted_at || sr.ended_at;
    kv([
      ["ID da sessão lacrada", sr.session_id],
      ["Encerramento da sessão", asDate(sr.ended_at)],
      ["Eventos registrados", sr.event_count],
      ["Merkle root da sessão", formatHashForDisplay(sr.merkle_root)],
      ["OriginStamp ID (BTC)", sr.originstamp_id || "Não emitido"],
      ["Status Bitcoin", srBtcAnchored
        ? "CONFIRMADO na blockchain Bitcoin (bloco minerado incluído no .ots)"
        : `Pendente desde a data de submissão do .ots (${asDate(srSubmittedAt)}) — RFC 3161 já constitui prova plena de anterioridade (MP 2.200-2/2001); a confirmação Bitcoin é redundância pública, tipicamente concluída em 1-6h`],
      ["Bloco Bitcoin", srBtcAnchored ? `#${sr.bitcoin_block_height}` : "Aguardando bloco (pendente)"],
      ["Confirmado em", srConfirmedAt ? asDate(srConfirmedAt) : "Aguardando bloco (pendente)"],
      ["Explorador", srExplorer],
    ]);

    // ISO 27037 — bloco de verificação independente para o perito adversário
    heading("Verificacao independente pelo perito adversario (ISO 27037)", 2);
    kv(buildIso27037PdfRows({
      evidenceHash: sr.merkle_root,
      otsSha256: sr.ots_sha256 ?? null,
      blockHeight: sr.bitcoin_block_height ?? null,
      blockHash: sr.block_hash ?? null,
      blockMerkleRoot: sr.block_merkle_root ?? null,
      blockTime: sr.block_time ?? null,
      calendars: sr.calendars,
      otsFilename: "sessao_lacrada.ots",
    }));

    if (sr.video_path) {
      heading("Dados do Video Forense", 2);
      kv([
        ["Arquivo", sr.video_path.split("/").pop() || sr.video_path],
        ["Caminho completo", sr.video_path],
        ["Bucket / storage", sr.video_bucket ?? "sealed-capture (privado)"],
        ["Tamanho", formatBytes(sr.video_size)],
        ["MIME type", sr.video_mime],
        ["Duracao", sr.video_duration_seconds != null ? `${sr.video_duration_seconds.toFixed(1)} segundos` : null],
        ["SHA-256 do video", formatHashForDisplay(sr.video_sha256)],
        ["Link assinado", sr.video_signed_url || "Nao gerado"],
        [
          "Validade do link",
          sr.video_signed_url_expires_at ? asDate(sr.video_signed_url_expires_at) + " (~30 dias)" : "N/A",
        ],
      ]);
      textBlock(
        "O video acima constitui registro audiovisual forense da sessao de navegacao. " +
          "A autenticidade do arquivo e verificavel pelo hash SHA-256 desta secao. " +
          "O link assinado permite acesso temporario ao arquivo no bucket privado.",
        { size: 9.5, italic: true },
      );
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PARTE I — Da Evidencia Capturada
  // ════════════════════════════════════════════════════════════════════════════

  partHeader(
    "I",
    "Da Evidencia Capturada",
    "Identificacao da fonte digital, URL e metadados de acesso ao conteudo preservado.",
  );

  heading("1.1 Identificacao da Fonte Digital", 2);
  kv([
    ["Rede social detectada", social?.network || "Pagina web / plataforma nao classificada"],
    ["Plataforma", social?.network || "Nao identificada automaticamente"],
    ["Handle / @conta", social?.handle || "Nao identificado automaticamente"],
    ["URL do perfil", social?.profileUrl || "Nao identificado automaticamente"],
    [
      "Dominio",
      (() => {
        try {
          return new URL(subjectUrl).hostname;
        } catch {
          return "Nao informado";
        }
      })(),
    ],
  ]);

  heading(isOffline ? "1.2 URL e Status de Resposta" : "1.2 URL e Status HTTP", 2);
  if (isOffline) {
    kv([
      ["URL solicitada (original)", result.original_url],
      ["URL final consultada", result.final_url || result.original_url],
      ["Timestamp da consulta", `${asDate(result.timestamp)} (${result.timestamp_source})`],
      ["Status do site", "FORA DO AR (sem resposta do servidor)"],
      ["Motivo tecnico", offlineReasonText],
      ["Codigo HTTP devolvido", offlineEv?.http_status != null ? String(offlineEv.http_status) : "Nao houve resposta HTTP"],
      ["IP de origem do operador", result.operator_ip || "Nao informado"],
      ["ID da requisicao", result.request_id || "Nao informado"],
    ]);

    // 1.3 — Constatação técnica (consultas DoH)
    heading("1.3 Constatacao Tecnica de Indisponibilidade (DNS-over-HTTPS)", 2);
    textBlock(
      "Para comprovar de forma independente que o site estava fora do ar no instante da coleta, foram " +
        "consultados dois resolvedores DNS públicos sob HTTPS (RFC 8484). Ambos retornaram ausência de " +
        "registros para o domínio. As respostas brutas estão preservadas no payload assinado por SHA-256.",
      { size: 9.5 },
    );
    const cfDns = offlineEv?.dns?.cloudflare;
    const ggDns = offlineEv?.dns?.google;
    kv([
      ["Cloudflare 1.1.1.1 - status", cfDns?.status || "sem resposta"],
      ["Cloudflare - registros A retornados", cfDns?.records?.length ? cfDns.records.join(", ") : "nenhum"],
      ["Cloudflare - excerpt da resposta", cfDns?.raw_excerpt || "n/d"],
      ["Google 8.8.8.8 - status", ggDns?.status || "sem resposta"],
      ["Google - registros A retornados", ggDns?.records?.length ? ggDns.records.join(", ") : "nenhum"],
      ["Google - excerpt da resposta", ggDns?.raw_excerpt || "n/d"],
      ["Consenso entre resolvedores", offlineEv?.dns_consensus || "n/d"],
      ["Wayback Machine - snapshot disponivel", offlineEv?.wayback?.available ? "Sim" : "Nao"],
    ]);
  } else {
    kv([
      ["URL solicitada (original)", result.original_url],
      ["URL final (apos redirecionamentos)", result.final_url],
      ["Codigo / slug da publicacao", postCode || "Nao identificado automaticamente"],
      ["Timestamp da captura", `${asDate(result.timestamp)} (${result.timestamp_source})`],
      ["Status HTTP", result.http_status],
      ["IP de origem do operador", result.operator_ip || "Nao informado"],
      ["ID da requisicao", result.request_id || "Nao informado"],
    ]);
  }


  if (result.page_title || result.page_description) {
    heading("1.3 Metadados da Pagina", 2);
    kv([
      ["Titulo declarado", result.page_title],
      ["Descricao (meta)", result.page_description],
    ]);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // ANEXO UNICO — Captura Visual (screenshot)
  // ════════════════════════════════════════════════════════════════════════════

  if (result.screenshot_base64 && result.screenshot_mime) {
    pdf.addPage();
    page += 1;
    y = MARGIN_TOP;

    heading("ANEXO UNICO - Captura Visual da Pagina");
    textBlock(
      "A imagem abaixo reproduz a captura visual integra da pagina preservada. " +
        "A integridade da imagem e verificavel pelo hash SHA-256 indicado abaixo. " +
        "Esta e a unica imagem de conteudo capturado embutida no documento.",
      { size: 10 },
    );
    y += 3;

    const dataUrl = `data:${result.screenshot_mime};base64,${result.screenshot_base64}`;
    const fmt = result.screenshot_mime.includes("png") ? "PNG" : "JPEG";
    try {
      const props = pdf.getImageProperties(dataUrl);
      // Sempre escala pela LARGURA disponível para nunca renderizar estreito.
      const imgW = CONTENT_W;
      const imgH = props.height * (CONTENT_W / props.width);

      // Fatiar verticalmente em páginas A4, mascarando sobras com retângulos brancos.
      let drawnH = 0;
      let firstSlice = true;
      while (drawnH < imgH - 0.01) {
        const availH = PAGE_H - y - MARGIN_BOTTOM;
        const sliceH = Math.min(availH, imgH - drawnH);
        // Desenha a imagem inteira deslocada para cima por `drawnH`.
        pdf.addImage(dataUrl, fmt, MARGIN_X, y - drawnH, imgW, imgH);
        // Máscaras brancas para esconder o que sai da fatia.
        pdf.setFillColor(255, 255, 255);
        if (y > 0) pdf.rect(0, 0, PAGE_W, y, "F"); // topo
        const bottomY = y + sliceH;
        if (bottomY < PAGE_H) pdf.rect(0, bottomY, PAGE_W, PAGE_H - bottomY, "F"); // fundo
        // Margens laterais (caso a imagem encoste, embora imgW = CONTENT_W).
        if (MARGIN_X > 0) {
          pdf.rect(0, 0, MARGIN_X, PAGE_H, "F");
          pdf.rect(PAGE_W - MARGIN_X, 0, MARGIN_X, PAGE_H, "F");
        }
        drawnH += sliceH;
        y = bottomY;
        firstSlice = false;
        if (drawnH < imgH - 0.01) {
          pdf.addPage();
          page += 1;
          y = MARGIN_TOP;
        }
      }
      y += 5;
      ensure(14);
      textBlock(`Legenda: Captura visual de ${subjectUrl}`, { size: 8.5, italic: true });
      textBlock(`SHA-256 da captura visual: ${result.screenshot_hash || "Nao informado"}`, { size: 8.5 });
      void firstSlice;
    } catch {
      textBlock(
        result.screenshot_warning ||
          "A captura visual nao pode ser embutida neste PDF, mas seus hashes permanecem registrados.",
        { size: 9.5, italic: true },
      );
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PARTE II — Integridade Criptografica
  // ════════════════════════════════════════════════════════════════════════════

  partHeader(
    "II",
    "Integridade Criptografica",
    "Hashes SHA-256 e SHA-512 do screenshot, HTML e codigo unico de evidencia.",
  );

  heading("2.1 Hash do Screenshot (SHA-256)", 2);
  const httpStatusNum = Number(result.http_status);
  const defaultObs = Number.isFinite(httpStatusNum) && httpStatusNum >= 400
    ? `Screenshot da resposta HTTP ${httpStatusNum} retornada pelo servidor (pagina de erro/bloqueio, nao o conteudo original).`
    : "Screenshot capturado com sucesso";
  if (isOffline) {
    kv([
      ["Algoritmo", "SHA-256 (FIPS 180-4)"],
      ["Hash do screenshot", "Nao aplicavel"],
      ["Observacao", "Nenhuma captura visual foi gerada porque o site estava fora do ar no instante da coleta (ver Aviso de Indisponibilidade no inicio do laudo e Secao 1.2). Esta Ata nao contem Anexo Unico."],
    ]);
  } else {
    kv([
      ["Algoritmo", "SHA-256 (FIPS 180-4)"],
      ["Hash do screenshot", formatHashForDisplay(result.screenshot_hash)],
      ["Observacao", result.screenshot_warning || defaultObs],
    ]);
  }

  heading("2.2 Hash do HTML Preservado (SHA-256)", 2);
  kv([
    ["Algoritmo", "SHA-256 (FIPS 180-4)"],
    ["Hash do HTML", formatHashForDisplay(result.html_hash)],
    ["Tamanho do HTML", formatBytes(result.html_size)],
    ["HTML truncado", result.html_truncated ? `Sim (tamanho original: ${formatBytes(result.html_full_size)})` : "Nao"],
    ...(isOffline ? [["Observacao", "Hash calculado sobre conteudo HTML vazio (e3b0c4...b855 e o SHA-256 da string vazia) - nenhum conteudo foi recebido do servidor."] as [string, string] ] : []),
  ]);


  heading("2.3 Codigo Unico da Evidencia", 2);
  textBlock(
    "O codigo unico abaixo e o hash SHA-256 de um documento JSON canonico. O calculo ocorre " +
      "em duas etapas encadeadas, descritas integralmente na Secao 2.5 (Metodologia de Recalculo), " +
      "de modo que qualquer perito possa reproduzir o valor de forma independente. Qualquer " +
      "alteracao em qualquer campo invalida este codigo.",
    { size: 9.5 },
  );

  y += 2;
  // Destaque visual para o hash principal
  pdf.setFillColor(240, 247, 244);
  pdf.setDrawColor(15, 76, 58);
  pdf.setLineWidth(0.4);
  pdf.rect(MARGIN_X, y - 3, CONTENT_W, 14);
  pdf.setFont("courier", "bold");
  pdf.setFontSize(9);
  pdf.setTextColor(15, 76, 58);
  const hashLines = pdf.splitTextToSize(formatHashForDisplay(result.evidence_hash), CONTENT_W - 4);
  pdf.text(hashLines, MARGIN_X + 2, y + 1);
  y += 16;
  note("SHA-256 da evidencia (acima) — use para verificacao independente em qualquer ferramenta de hash.");

  heading("2.4 Hash Espelho SHA-512", 2);
  kv([
    ["Algoritmo", "SHA-512 (FIPS 180-4)"],
    ["Hash SHA-512", formatHashForDisplay(result.evidence_hash_sha512)],
  ]);
  note(
    "O hash SHA-512 e calculado sobre os mesmos dados do SHA-256 e serve como espelho " +
      "para resistencia a colisao a longo prazo.",
  );

  heading("2.5 Metodologia de Recalculo do Codigo Unico (receita v1)", 2);
  textBlock(
    "Especificacao completa para reproducao independente do Codigo Unico. Todos os valores " +
      "sao serializados em UTF-8 com JSON.stringify (ECMA-404), sem espacos, na ordem exata " +
      "de insercao das chaves listadas abaixo. Timestamps em ISO 8601 UTC com milissegundos " +
      "(formato YYYY-MM-DDTHH:MM:SS.sssZ), conforme Date.prototype.toISOString().",
    { size: 9.5 },
  );
  kv([
    ["Versao da receita", "v1"],
    ["Encoding", "UTF-8"],
    ["Serializacao", "JSON.stringify (ECMA-404), sem indentacao, ordem de insercao das chaves"],
    ["Algoritmos", "SHA-256 e SHA-512 (FIPS 180-4), saida em hexadecimal minusculo"],
    ["Formato de data", "ISO 8601 UTC com 3 digitos de milissegundo (toISOString)"],
  ]);
  textBlock(
    "Etapa 1 — hash do servidor (H1). Calculado pelo coletor sobre um objeto JSON com as " +
      "chaves, nesta ordem: url_requested, final_url, timestamp_utc, timestamp_source, " +
      "timestamp_response_hash, http_status, html_hash, html_truncated, html_full_size, " +
      "rendered_dom_hash, rendered_dom_size, rendered_dom_source, screenshot_hash, " +
      "screenshot_provider, screenshot_provider_request_id, screenshot_provider_headers_hash, " +
      "screenshot_provider_edge_region, screenshot_fetched_at, security_headers, reachability, " +
      "operator_ip, request_id, previous_evidence_hash. H1 = SHA-256(JSON).",
    { size: 9.5 },
  );
  textBlock(
    "Etapa 2 — hash composto (Codigo Unico). Sobre H1 aplica-se a identificacao do solicitante, " +
      'em um segundo JSON com as chaves abreviadas nesta ordem: {"h": H1 em minusculo, ' +
      '"u": UID do operador, "n": nome, "e": e-mail, "c": CPF formatado ou string vazia, ' +
      '"cg": cargo ou string vazia, "t": timestamp de submissao ISO 8601, "i": IP do operador ' +
      'apurado pelo servidor ou "unknown", "r": request_id do servidor}. ' +
      "Codigo Unico = SHA-256(JSON). O hash espelho e SHA-512 do mesmo JSON.",
    { size: 9.5 },
  );
  textBlock(
    "Pseudocodigo de verificacao: " +
      "H1 = sha256(utf8(json_canonico_etapa_1)); " +
      "codigo_unico = sha256(utf8(json_canonico_etapa_2(H1, identificacao))). " +
      "Todos os valores de entrada das duas etapas constam impressos neste laudo " +
      "(Partes I, II e V), permitindo o recalculo integral sem acesso a plataforma.",
    { size: 9.5 },
  );



  // ════════════════════════════════════════════════════════════════════════════
  // PARTE III — Ancoragem Temporal
  // ════════════════════════════════════════════════════════════════════════════

  partHeader(
    "III",
    "Ancoragem Temporal",
    "Carimbos de tempo OpenTimestamps (Bitcoin blockchain) e RFC 3161 (FreeTSA).",
  );

  heading("3.1 OpenTimestamps (OTS / Bitcoin)", 2);
  if (input.stamp) {
    const st = input.stamp;
    // Correção crítica (ver bloco Sealed acima): "CONFIRMADO" só quando há bloco Bitcoin real.
    const isBtcConfirmed = !!st.bitcoin_block_height;
    const btcConfirmedAt = isBtcConfirmed ? (st.ots_confirmed_at || st.verified_at || null) : null;
    const btcExplorer = isBtcConfirmed
      ? `https://mempool.space/block/${st.bitcoin_block_height}`
      : "https://mempool.space (aguardando agregação em bloco Bitcoin — tipicamente 1-6h)";
    kv([
      ["Data de submissão", asDate(st.submitted_at)],
      ["Data de confirmação", isBtcConfirmed ? asDate(st.date_created) : "Aguardando bloco (pendente)"],
      ["Hash submetido", formatHashForDisplay(result.evidence_hash)],
      ["Moedas de ancoragem", (st.currencies || []).join(", ") || "BTC / ETH / IPFS"],
      ["ID OTS", st.timestamp_id],
      ["Status Bitcoin", isBtcConfirmed
        ? "CONFIRMADO na blockchain Bitcoin (bloco minerado incluído no .ots)"
        : `Pendente desde a data de submissão do .ots (${asDate(st.submitted_at)}) — RFC 3161 já constitui prova plena de anterioridade (MP 2.200-2/2001); a confirmação Bitcoin é redundância pública, tipicamente concluída em 1-6h`],
      ["Bloco Bitcoin", isBtcConfirmed ? `#${st.bitcoin_block_height}` : "Aguardando bloco (pendente)"],
      ["Confirmado em", btcConfirmedAt ? asDate(btcConfirmedAt) : "Aguardando bloco (pendente)"],
      ["Explorador", btcExplorer],
    ]);
    textBlock(
      isBtcConfirmed
        ? "O OpenTimestamps comprova que o hash da evidência existia antes do bloco Bitcoin " +
          "indicado. Para verificação independente: instale o cliente ots (opentimestamps.org) " +
          "e execute: ots verify evidencia.ots"
        : "O carimbo RFC 3161 (FreeTSA) já é prova plena de anterioridade (MP 2.200-2/2001). " +
          "A confirmação Bitcoin via OpenTimestamps é redundância pública; o .ots agrega em " +
          "bloco em 1-6h e pode ser reverificado a qualquer momento com: ots verify evidencia.ots",
      { size: 9.5 },
    );

    // ISO 27037 — bloco de verificação independente para o perito adversário
    heading("Verificacao independente pelo perito adversario (ISO 27037)", 2);
    kv(buildIso27037PdfRows({
      evidenceHash: result.evidence_hash,
      otsSha256: st.ots_sha256 ?? null,
      blockHeight: st.bitcoin_block_height ?? null,
      blockHash: st.block_hash ?? null,
      blockMerkleRoot: st.block_merkle_root ?? null,
      blockTime: st.block_time ?? null,
      calendars: st.calendars,
      otsFilename: st.ots_filename || "evidence.ots",
    }));
  } else {
    kv([
      ["Status", "Nao emitido ate a geracao do PDF"],
      ["Instrucao", "Gere o carimbo OTS antes de emitir o laudo para ancoragem Bitcoin completa"],
    ]);
  }

  heading("3.2 RFC 3161 / FreeTSA", 2);
  if (input.stamp?.rfc3161_timestamp) {
    kv([
      ["Autoridade de timestamping", "FreeTSA (freetsa.org)"],
      ["Data de emissao", asDate(input.stamp.rfc3161_timestamp)],
      ["Norma", "RFC 3161 - Internet X.509 PKI Time-Stamp Protocol"],
    ]);
    note(
      "O token RFC 3161 e emitido por autoridade de timestamping reconhecida e pode ser " +
        "verificado com OpenSSL: openssl ts -verify -data evidencia.bin -in evidencia.tsr",
    );
  } else {
    kv([["Status", "Nao emitido ate a geracao do PDF"]]);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PARTE IV — Validacao Publica
  // ════════════════════════════════════════════════════════════════════════════

  partHeader("IV", "Validacao Publica", "QR Code e URL para verificacao independente da integridade desta evidencia.");

  textBlock(
    "Qualquer pessoa pode verificar a integridade desta evidencia apontando a camera do celular " +
      "para o QR code abaixo, ou acessando a URL de validacao pelo navegador.",
    { size: 10 },
  );
  y += 3;

  // QR Code
  if (qrDataUrl) {
    ensure(55);
    try {
      pdf.addImage(qrDataUrl, "PNG", MARGIN_X, y, 42, 42);
      const qrRight = MARGIN_X + 47;
      const qrTop = y + 5;
      pdf.setFont("times", "bold");
      pdf.setFontSize(10);
      pdf.setTextColor(15, 76, 58);
      pdf.text("Verificacao online:", qrRight, qrTop);
      pdf.setFont("times", "normal");
      pdf.setFontSize(8.5);
      pdf.setTextColor(30, 30, 30);
      const urlLines = pdf.splitTextToSize(verifyUrl, CONTENT_W - 47);
      pdf.text(urlLines, qrRight, qrTop + 6);
      pdf.setFontSize(8.5);
      pdf.setTextColor(80, 80, 80);
      pdf.text("1. Aponte a camera do celular para o QR Code", qrRight, qrTop + 18);
      pdf.text("2. Ou acesse a URL acima pelo navegador", qrRight, qrTop + 23);
      pdf.text("3. Informe o hash SHA-256 da evidencia", qrRight, qrTop + 28);
      pdf.text("4. O sistema confirma a integridade em tempo real", qrRight, qrTop + 33);
      y += 47;
    } catch {
      kv([["URL de verificacao", verifyUrl]]);
    }
  } else {
    kv([
      ["URL de verificacao", verifyUrl],
      ["Hash para verificar", result.evidence_hash],
    ]);
  }

  note(
    "O QR code aponta para o verificador publico Trace Hub. A URL inclui o hash da evidencia para validacao automatica.",
  );

  // ════════════════════════════════════════════════════════════════════════════
  // PARTE V — Snapshot de Infraestrutura
  // ════════════════════════════════════════════════════════════════════════════

  if (result.networkMetadata) {
    const nm = result.networkMetadata;

    partHeader(
      "V",
      "Snapshot de Infraestrutura",
      "RDAP, DNS, SSL/TLS e dados de atribuicao do dominio no momento da captura.",
    );

    heading("5.1 RDAP (Dados de Registro do Dominio)", 2);
    const rdap = nm.rdap;
    if (rdap && !("error" in rdap && !rdap.ldhName)) {
      kv([
        ["Dominio (LDH)", rdap.ldhName],
        ["Handle", rdap.handle],
        ["Status", (rdap.status || []).join(", ") || "Nao informado"],
        ["Registrar", rdap.registrar],
        ["Registro", rdap.events?.registration],
        ["Expiracao", rdap.events?.expiration],
        ["Nameservers", (rdap.nameservers || []).join(", ")],
      ]);
    } else {
      kv([["Status", (rdap as { error?: string }).error || "RDAP indisponivel para este dominio"]]);
    }

    heading("5.2 Registros DNS", 2);
    const dnsTypes = ["A", "AAAA", "MX", "NS", "TXT", "CAA"] as const;
    const dnsRows: Array<[string, string]> = [];
    for (const t of dnsTypes) {
      const recs = nm.dns?.[t];
      if (recs && recs.length > 0) {
        dnsRows.push([`DNS ${t}`, recs.map((r) => `${r.data} (TTL ${r.ttl})`).join(" | ")]);
      } else {
        dnsRows.push([`DNS ${t}`, "Sem registros"]);
      }
    }
    kv(dnsRows);

    heading("5.3 SSL/TLS", 2);
    const tls = nm.tls;
    if (tls && !("error" in tls && !(tls as { issuer?: unknown }).issuer)) {
      const t = tls as {
        subject?: unknown;
        issuer?: unknown;
        validFrom?: string;
        validTo?: string;
        serialNumber?: string;
        san?: string[];
      };
      kv([
        ["Emissor", String(t.issuer || "Nao informado")],
        ["Assunto", String(t.subject || "Nao informado")],
        ["Valido de", t.validFrom],
        ["Valido ate", t.validTo],
        ["Serial", t.serialNumber],
        ["SANs", (t.san || []).slice(0, 6).join(", ")],
      ]);
    } else {
      kv([["Status TLS", (tls as { error?: string }).error || "TLS indisponivel"]]);
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PARTE VI — Verificacoes Tecnicas Complementares
  // ════════════════════════════════════════════════════════════════════════════

  if (result.dnsIntegrity || result.networkMetadata) {
    partHeader(
      "VI",
      "Verificacoes Tecnicas Complementares",
      "Integridade DNS multi-resolver e metadados de rede complementares.",
    );

    if (result.dnsIntegrity) {
      const di = result.dnsIntegrity;
      heading("6.1 Integridade DNS (Anti-DNS-Poisoning)", 2);

      // Reclassificação do rótulo com base na TAXA DE SUCESSO (não apenas concordância).
      // A sonda usa 2 resolvers DoH independentes e estáveis (Google × Cloudflare).
      // Quorum mínimo para "consenso forte": 2 de 2 resolvers respondendo E concordando.
      const TOTAL_RESOLVERS = 2;
      const responded = Number(di.responding_resolvers ?? 0);
      const failed = Math.max(0, TOTAL_RESOLVERS - responded);
      const failureDetail = (di.resolver_chain?.a ?? [])
        .filter((r: any) => r?.error)
        .map((r: any) => `${r.resolver}: ${String(r.error).slice(0, 60)}`)
        .join("; ");
      const failuresNote = failed > 0
        ? ` (${responded} de ${TOTAL_RESOLVERS} resolvers responderam; ${failed} falharam por timeout/bloqueio)`
        : ` (${responded} de ${TOTAL_RESOLVERS} resolvers responderam)`;

      const engineLevel = di.dns_consensus_level;
      const concordant =
        engineLevel === "consensus_strong" || engineLevel === "consensus_anycast" || engineLevel === "consensus_partial";

      let consensusLabel: string;
      if (concordant && responded >= 2) {
        const basis = engineLevel === "consensus_anycast" ? "mesmo ASN" : "mesmo prefixo /24 ou /48";
        consensusLabel = `Consenso forte — ${basis} entre os resolvers respondentes, com quorum minimo de 2/2 atendido${failuresNote}`;
      } else if (engineLevel === "divergent") {
        consensusLabel = `Divergente — possivel envenenamento DNS${failuresNote}`;
      } else {
        consensusLabel = `Inconclusivo — apenas ${responded} de ${TOTAL_RESOLVERS} resolvedores respondeu, abaixo do quorum minimo de 2/2${failuresNote}`;
      }


      kv([
        ["Status de consenso", consensusLabel],
        ["IPs consensuais", (di.consensus_ips || []).join(", ") || "Nao identificado"],
        ["Metodo", di.method],
        ["Resolvers consultados", `${responded} de ${TOTAL_RESOLVERS} responderam`],
        ...(failureDetail ? [["Resolvers que falharam", failureDetail] as [string, string]] : []),
        ["Capturado em", asDate(di.captured_at_utc)],
      ]);


      // Tabela de resolvers
      if (di.resolver_chain?.a?.length) {
        heading("Tabela de Resolvers IPv4 (A)", 2);
        y += 1;
        // Header
        const colW = [50, 65, 30, 29];
        const headers = ["Resolver", "IPs retornados", "RTT (ms)", "Status"];
        pdf.setFillColor(15, 76, 58);
        pdf.rect(MARGIN_X, y - 3.5, CONTENT_W, 8, "F");
        pdf.setFont("times", "bold");
        pdf.setFontSize(8.5);
        pdf.setTextColor(255, 255, 255);
        let cx = MARGIN_X + 2;
        headers.forEach((h, i) => {
          pdf.text(h, cx, y);
          cx += colW[i];
        });
        y += 5;
        di.resolver_chain.a.forEach((r, idx) => {
          const rowH = 7;
          ensure(rowH);
          pdf.setFillColor(idx % 2 === 0 ? 248 : 255, 250, 248);
          pdf.rect(MARGIN_X, y - 3.5, CONTENT_W, rowH, "F");
          pdf.setDrawColor(220, 230, 225);
          pdf.setLineWidth(0.15);
          pdf.rect(MARGIN_X, y - 3.5, CONTENT_W, rowH);
          pdf.setFont("courier", "normal");
          pdf.setFontSize(7.8);
          pdf.setTextColor(25, 25, 25);
          cx = MARGIN_X + 2;
          const cells = [r.resolver, (r.ips || []).join(", ") || "—", `${r.rttMs}`, r.error ? "ERRO" : "OK"];
          cells.forEach((c, i) => {
            const cellLines = pdf.splitTextToSize(cleanText(c), colW[i] - 3);
            pdf.text(cellLines[0] ?? "", cx, y);
            cx += colW[i];
          });
          y += rowH + 0.5;
        });
        y += 3;
      }
    }

    if (result.networkMetadata) {
      heading("6.2 Metadados de Rede (Resumo)", 2);
      const nm = result.networkMetadata;
      kv([
        ["Host", nm.host],
        ["Dominio registravel", nm.registrable_domain],
        ["Capturado em", asDate(nm.captured_at_utc)],
      ]);
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // ASSINATURA DO OPERADOR RESPONSAVEL PELA COLETA
  // ════════════════════════════════════════════════════════════════════════════
  ensure(34);
  y += 12;
  drawSignaturePDF(
    pdf,
    {
      mode: ((input.author?.mode as AuthorMode) || "perito"),
      fullName: input.author?.name || input.requester?.name || "",
      registroProfissional: input.author?.registry || undefined,
      cargoFuncao: input.author?.title || undefined,
    },
    { pageWidth: PAGE_W, y },
  );

  // ════════════════════════════════════════════════════════════════════════════
  // RODAPE em todas as paginas
  // ════════════════════════════════════════════════════════════════════════════

  const total = pdf.getNumberOfPages();
  for (let i = 1; i <= total; i++) {
    pdf.setPage(i);

    // Cabecalho
    pdf.setFont("times", "bold");
    pdf.setFontSize(7.5);
    pdf.setTextColor(15, 76, 58);
    pdf.text("ATA NOTARIAL DIGITAL  ·  TRACE HUB", MARGIN_X, 10);
    pdf.setFont("times", "normal");
    pdf.setFontSize(7);
    pdf.setTextColor(130, 130, 130);
    pdf.text(`Evidencia: ${shortHash}  |  Gerado: ${generatedAt.toLocaleDateString("pt-BR")}`, PAGE_W - MARGIN_X, 10, {
      align: "right",
    });
    pdf.setDrawColor(15, 76, 58);
    pdf.setLineWidth(0.4);
    pdf.line(MARGIN_X, 13, PAGE_W - MARGIN_X, 13);

    // Rodape
    pdf.setDrawColor(200, 200, 200);
    pdf.setLineWidth(0.2);
    pdf.line(MARGIN_X, PAGE_H - 14, PAGE_W - MARGIN_X, PAGE_H - 14);
    pdf.setFont("times", "normal");
    pdf.setFontSize(7);
    pdf.setTextColor(110, 110, 110);
    pdf.text("CPC art. 411 II  ·  MP 2.200-2/2001  ·  ISO/IEC 27037  ·  Provimento CNJ 100/2020", MARGIN_X, PAGE_H - 9);
    pdf.setFont("courier", "normal");
    pdf.setFontSize(7);
    pdf.setTextColor(15, 76, 58);
    pdf.text(shortHash, PAGE_W / 2, PAGE_H - 9, { align: "center" });
    pdf.setFont("times", "normal");
    pdf.setTextColor(110, 110, 110);
    pdf.text(`Pagina ${i} de ${total}`, PAGE_W - MARGIN_X, PAGE_H - 9, { align: "right" });
  }

  return pdf;
}

// ─── API pública ───────────────────────────────────────────────────────────────

export async function exportTextualNotarialPDF(
  input: NotarialTextPdfInput,
  filename: string,
  popupWindow?: Window | null,
): Promise<{ blob: Blob; base64: string }> {
  const pdf = await buildTextualNotarialPDF(input);
  const blob = pdf.output("blob") as Blob;
  downloadBlob(blob, filename, popupWindow);
  const ab = pdf.output("arraybuffer") as ArrayBuffer;
  return { blob, base64: arrayBufferToBase64(ab) };
}

export async function textualNotarialPDFToBase64(input: NotarialTextPdfInput): Promise<string> {
  const pdf = await buildTextualNotarialPDF(input);
  return arrayBufferToBase64(pdf.output("arraybuffer") as ArrayBuffer);
}

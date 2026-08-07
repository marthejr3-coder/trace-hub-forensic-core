/**
 * Section-aware PDF export.
 *
 * Itera sobre filhos com [data-pdf-section] dentro de `rootEl`, renderiza cada
 * seção isoladamente via html2canvas e adiciona ao PDF respeitando a quebra
 * natural de página (não corta um bloco no meio). Cabeçalho e rodapé são
 * desenhados via API vetorial do jsPDF para garantir nitidez tipográfica.
 *
 * Exceção: o screenshot (seção marcada com data-pdf-tall="true") é fatiado
 * ao longo de várias páginas, mantendo um título de continuação no topo.
 */

import { getJsPDF, getHtml2Canvas } from '@/lib/jspdf-safe';
import { ensureForensicFontsLoaded } from '@/lib/forensic-fonts';
import { downloadBlob } from '@/lib/ios-download';
import { collectTextItems, drawInvisibleTextLayer } from '@/lib/pdf-text-overlay';

const A4_WIDTH_MM = 210;
const A4_HEIGHT_MM = 297;
const MARGIN_TOP_MM = 18;
const MARGIN_BOTTOM_MM = 16;
const MARGIN_X_MM = 12;

const USABLE_WIDTH_MM = A4_WIDTH_MM - MARGIN_X_MM * 2;
const PAGE_CONTENT_TOP_MM = MARGIN_TOP_MM;
const PAGE_CONTENT_BOTTOM_MM = A4_HEIGHT_MM - MARGIN_BOTTOM_MM;
const PAGE_CONTENT_HEIGHT_MM = PAGE_CONTENT_BOTTOM_MM - PAGE_CONTENT_TOP_MM;

// Limite seguro de altura de canvas em browsers móveis (Safari iOS ≈ 16384px,
// alguns Android Chrome ≈ 16384px). Usamos margem para encolher antes.
const MAX_SAFE_CANVAS_PX = 14000;

interface ExportOpts {
  /** Hash composto curto para mostrar no rodapé (ex: primeiros 16 chars). */
  shortHash?: string;
}

/** Sanitiza cores modernas (oklch/lab/color-mix) que html2canvas não suporta. */
function sanitizeModernColors(clonedDoc: Document) {
  const all = clonedDoc.querySelectorAll<HTMLElement>('*');
  all.forEach((node) => {
    try {
      const cs = clonedDoc.defaultView?.getComputedStyle(node);
      if (!cs) return;
      const bad = (v: string | null | undefined) =>
        !!v && (v.includes('oklch') || v.includes('lab(') || v.includes('color-mix'));
      if (bad(cs.color)) node.style.color = '#1a1a1a';
      if (bad(cs.backgroundColor)) node.style.backgroundColor = '#ffffff';
      if (bad(cs.borderColor)) node.style.borderColor = '#e5e7eb';
      // Neutraliza text-align:justify — quando combinado com larguras estreitas
      // em mobile, gera letter-spacing extremo ("D O C U M E N T O") no PDF.
      if (cs.textAlign === 'justify') node.style.textAlign = 'left';
    } catch {
      /* noop */
    }
  });
}

/**
 * Força o `rootEl` a uma largura desktop fixa durante a geração do PDF,
 * evitando que layouts mobile (text-justify estreito, quebras agressivas)
 * vazem para o A4. Retorna função de restauração.
 */
const DESKTOP_PDF_WIDTH_PX = 1024;
function lockDesktopWidth(rootEl: HTMLElement): () => void {
  const prev = {
    width: rootEl.style.width,
    minWidth: rootEl.style.minWidth,
    maxWidth: rootEl.style.maxWidth,
    boxSizing: rootEl.style.boxSizing,
  };
  rootEl.style.width = `${DESKTOP_PDF_WIDTH_PX}px`;
  rootEl.style.minWidth = `${DESKTOP_PDF_WIDTH_PX}px`;
  rootEl.style.maxWidth = `${DESKTOP_PDF_WIDTH_PX}px`;
  rootEl.style.boxSizing = 'border-box';
  // Força reflow para o layout assentar antes do html2canvas medir.
  // eslint-disable-next-line @typescript-eslint/no-unused-expressions
  rootEl.offsetHeight;
  return () => {
    rootEl.style.width = prev.width;
    rootEl.style.minWidth = prev.minWidth;
    rootEl.style.maxWidth = prev.maxWidth;
    rootEl.style.boxSizing = prev.boxSizing;
  };
}

function pickScale(el: HTMLElement): number {
  // Largura agora é travada em DESKTOP_PDF_WIDTH_PX antes da captura, então
  // usamos escala 2 padrão; só reduzimos se o canvas estimado estourar.
  let scale = 2;
  const estHeight = el.getBoundingClientRect().height * scale;
  if (estHeight > MAX_SAFE_CANVAS_PX) {
    scale = Math.max(1, (MAX_SAFE_CANVAS_PX / el.getBoundingClientRect().height) * 0.95);
  }
  return scale;
}

async function renderSection(
  el: HTMLElement,
  html2canvas: any,
): Promise<{ canvas: HTMLCanvasElement; scale: number }> {
  const scale = pickScale(el);
  const canvas = await html2canvas(el, {
    scale,
    backgroundColor: '#ffffff',
    useCORS: true,
    logging: false,
    onclone: sanitizeModernColors,
  });
  return { canvas, scale };
}

/**
 * Bloco 4 — Coleta zonas (em pixels do canvas) que NÃO podem ser cortadas
 * entre páginas. Marcadas com [data-pdf-keep] em ReportField, HashHighlight,
 * SummaryRow, PartHeader, OpenTimestampsStatus, anexo de imagem etc.
 *
 * Também trata <img> e <table> implicitamente como blocos atômicos.
 */
function collectKeepZones(section: HTMLElement, scale: number): Array<[number, number]> {
  const sectionTop = section.getBoundingClientRect().top;
  const selector = '[data-pdf-keep], img, table';
  const nodes = Array.from(section.querySelectorAll<HTMLElement>(selector));
  const zones: Array<[number, number]> = [];
  for (const node of nodes) {
    const rect = node.getBoundingClientRect();
    if (rect.height <= 0) continue;
    // Pula nós que estão DENTRO de outro [data-pdf-keep] — o ancestral cobre tudo.
    const ancestorKeep = node.parentElement?.closest('[data-pdf-keep]');
    if (ancestorKeep && section.contains(ancestorKeep) && ancestorKeep !== node) continue;
    const top = (rect.top - sectionTop) * scale;
    const bottom = top + rect.height * scale;
    zones.push([Math.max(0, top), bottom]);
  }
  // Ordena por topo asc (não precisa fundir — buscamos cada uma na hora do corte).
  zones.sort((a, b) => a[0] - b[0]);
  return zones;
}

/**
 * Dado um corte proposto em `cutPx` (no espaço do canvas), retorna o maior
 * `cutPx'` ≤ cutPx que NÃO esteja dentro de nenhuma zona protegida. Se não
 * achar (zona maior que a página), devolve o `cutPx` original.
 */
function adjustCutForKeepZones(
  cutPx: number,
  startPx: number,
  zones: Array<[number, number]>,
): number {
  for (const [top, bottom] of zones) {
    if (cutPx > top && cutPx < bottom) {
      // Recua para o topo da zona — mas nunca antes do início da página.
      const candidate = Math.floor(top);
      if (candidate > startPx + 4) return candidate;
      // Zona é maior que uma página inteira: corta mesmo (caso raro).
      return cutPx;
    }
  }
  return cutPx;
}

function drawHeader(pdf: any) {
  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(7.5);
  pdf.setTextColor(120, 120, 120);
  pdf.text('ATA NOTARIAL DIGITAL · TRACE HUB', MARGIN_X_MM, 10);
  pdf.setDrawColor(15, 76, 58);
  pdf.setLineWidth(0.4);
  pdf.line(MARGIN_X_MM, 12, A4_WIDTH_MM - MARGIN_X_MM, 12);
}

function drawFooter(
  pdf: any,
  pageNum: number,
  totalPages: number,
  shortHash?: string,
) {
  pdf.setDrawColor(200, 200, 200);
  pdf.setLineWidth(0.2);
  pdf.line(MARGIN_X_MM, A4_HEIGHT_MM - 11, A4_WIDTH_MM - MARGIN_X_MM, A4_HEIGHT_MM - 11);

  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(7);
  pdf.setTextColor(110, 110, 110);
  pdf.text('CPC art. 411 II · MP 2.200-2/2001', MARGIN_X_MM, A4_HEIGHT_MM - 6);

  if (shortHash) {
    pdf.setFont('courier', 'normal');
    pdf.setFontSize(7);
    pdf.text(shortHash, A4_WIDTH_MM / 2, A4_HEIGHT_MM - 6, { align: 'center' });
  }

  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(7);
  pdf.text(
    `Página ${pageNum} de ${totalPages}`,
    A4_WIDTH_MM - MARGIN_X_MM,
    A4_HEIGHT_MM - 6,
    { align: 'right' },
  );
}

/**
 * Constrói o objeto jsPDF (sem salvar). Usado por `exportSectionedPDF` e
 * `sectionedPDFToBase64` — eliminando geração dupla.
 */
async function buildPDF(rootEl: HTMLElement, opts: ExportOpts = {}) {
  // Garante fontes cartoriais carregadas — crítico para layout correto no mobile.
  await ensureForensicFontsLoaded();

  const html2canvas = getHtml2Canvas();
  const jsPDF = getJsPDF();

  // Trava o report em largura desktop antes de qualquer medição/captura.
  // Sem isso, geração de PDF no mobile herda layout responsivo estreito
  // e produz texto justificado letra-a-letra ("D O C U M E N T O").
  const restoreWidth = lockDesktopWidth(rootEl);

  try {
  const sections = Array.from(
    rootEl.querySelectorAll<HTMLElement>('[data-pdf-section]'),
  );

  if (sections.length === 0) {
    throw new Error('Nenhuma seção [data-pdf-section] encontrada para exportar.');
  }

  const pdf = new jsPDF('p', 'mm', 'a4');
  let cursorY = PAGE_CONTENT_TOP_MM;
  let pageCount = 1;

  const newPage = () => {
    pdf.addPage();
    pageCount++;
    cursorY = PAGE_CONTENT_TOP_MM;
  };

  const sectionErrors: string[] = [];

  for (let idx = 0; idx < sections.length; idx++) {
    const section = sections[idx];
    try {
      const isTall = section.dataset.pdfTall === 'true';
      const breakBefore = section.dataset.pdfBreakBefore === 'true';
      const breakAfter = section.dataset.pdfBreakAfter === 'true';
      const isPartHeader = !!section.querySelector('[data-pdf-part-header]');
      const keepTogether = section.dataset.pdfKeepTogether === 'true';

      if (breakBefore && cursorY > PAGE_CONTENT_TOP_MM + 1) {
        newPage();
      }

      const { canvas, scale } = await renderSection(section, html2canvas);
      const heightMM = (canvas.height * USABLE_WIDTH_MM) / canvas.width;
      const keepZones = collectKeepZones(section, scale);

      // Camada de texto invisível: coletada ANTES do html2canvas reflowar
      // estilos no clone, mas como collectTextItems lê do DOM vivo, fazemos
      // aqui (DOM real já foi medido pelo html2canvas com a mesma largura).
      const sectionWidthCss = section.getBoundingClientRect().width || 1;
      const mmPerPxCss = USABLE_WIDTH_MM / sectionWidthCss;
      const textItems = collectTextItems(section);

      // Bloco 4 — Não deixar título de Parte sozinho no fim da página.
      if (isPartHeader && !isTall) {
        const next = sections[idx + 1];
        const minNextMM = 30;
        if (next) {
          const remaining = PAGE_CONTENT_BOTTOM_MM - cursorY;
          if (remaining < heightMM + minNextMM && cursorY > PAGE_CONTENT_TOP_MM + 1) {
            newPage();
          }
        }
      }

      if (!isTall) {
        const remaining = PAGE_CONTENT_BOTTOM_MM - cursorY;
        if (heightMM > remaining && cursorY > PAGE_CONTENT_TOP_MM + 1) {
          newPage();
        }
        const fitsOnFreshPage = heightMM <= PAGE_CONTENT_HEIGHT_MM;
        if (keepTogether && heightMM > PAGE_CONTENT_BOTTOM_MM - cursorY && cursorY > PAGE_CONTENT_TOP_MM + 1) {
          newPage();
        }
        if (fitsOnFreshPage) {
          const imgData = canvas.toDataURL('image/jpeg', 0.92);
          pdf.addImage(imgData, 'JPEG', MARGIN_X_MM, cursorY, USABLE_WIDTH_MM, heightMM);
          drawInvisibleTextLayer(pdf, textItems, mmPerPxCss, MARGIN_X_MM, cursorY);
          const gap = (PAGE_CONTENT_BOTTOM_MM - (cursorY + heightMM)) < 5 ? 0 : 3;
          cursorY += heightMM + gap;
          continue;
        }
      }

      // Fatiamento com respeito às keep-zones (Bloco 4 — quebras de página)
      const pxPerMM = canvas.width / USABLE_WIDTH_MM;
      let drawnPx = 0;

      while (drawnPx < canvas.height) {
        const remaining = PAGE_CONTENT_BOTTOM_MM - cursorY;
        if (remaining < 25 && cursorY > PAGE_CONTENT_TOP_MM + 1) {
          newPage();
        }
        const availablePx = (PAGE_CONTENT_BOTTOM_MM - cursorY) * pxPerMM;
        const remainingPx = canvas.height - drawnPx;
        let sliceHeightPx = Math.floor(Math.min(availablePx, remainingPx));

        // Se este corte cair no meio de uma keep-zone, recua para o topo dela.
        if (sliceHeightPx < remainingPx) {
          const cutAbsolute = drawnPx + sliceHeightPx;
          const adjusted = adjustCutForKeepZones(cutAbsolute, drawnPx, keepZones);
          if (adjusted < cutAbsolute) {
            sliceHeightPx = adjusted - drawnPx;
          }
        }
        // Mínimo defensivo (zonas grandes podem zerar; aceita o original)
        if (sliceHeightPx <= 0) {
          sliceHeightPx = Math.floor(Math.min(availablePx, remainingPx));
        }

        const sliceCanvas = document.createElement('canvas');
        sliceCanvas.width = canvas.width;
        sliceCanvas.height = sliceHeightPx;
        const ctx = sliceCanvas.getContext('2d')!;
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, sliceCanvas.width, sliceCanvas.height);
        ctx.drawImage(canvas, 0, -drawnPx);

        const sliceData = sliceCanvas.toDataURL('image/jpeg', 0.88);
        const realSliceMM = sliceHeightPx / pxPerMM;
        pdf.addImage(sliceData, 'JPEG', MARGIN_X_MM, cursorY, USABLE_WIDTH_MM, realSliceMM);

        // Camada de texto invisível desta fatia (converte canvas px → CSS px).
        const sliceTopCss = drawnPx / scale;
        const sliceBottomCss = (drawnPx + sliceHeightPx) / scale;
        drawInvisibleTextLayer(
          pdf,
          textItems,
          mmPerPxCss,
          MARGIN_X_MM,
          cursorY,
          sliceTopCss,
          sliceBottomCss,
        );

        drawnPx += sliceHeightPx;
        cursorY += realSliceMM + 2;

        if (drawnPx < canvas.height) {
          newPage();
        }
      }

      // Quebra forçada após a seção (ex.: frontispício precisa ocupar página sozinho)
      if (breakAfter && cursorY > PAGE_CONTENT_TOP_MM + 1) {
        newPage();
      }
    } catch (sectionErr: any) {
      console.error(`[PDF] Falha ao renderizar seção #${idx}`, section, sectionErr);
      sectionErrors.push(`#${idx}: ${sectionErr?.message || sectionErr}`);
    }
  }
  if (sectionErrors.length === sections.length) {
    throw new Error(`Nenhuma seção renderizada. Erros: ${sectionErrors.join(' | ')}`);
  }

  // Header/footer vetorial em todas as páginas
  const totalPages = pageCount;
  for (let i = 1; i <= totalPages; i++) {
    pdf.setPage(i);
    drawHeader(pdf);
    drawFooter(pdf, i, totalPages, opts.shortHash);
  }

  return pdf;
  } finally {
    restoreWidth();
  }
}

// Download universal delegado ao utilitário central `ios-download.ts`.

export async function exportSectionedPDF(
  rootEl: HTMLElement,
  filename: string,
  opts: ExportOpts = {},
  popupWindow?: Window | null,
): Promise<{ blob: Blob; base64: string }> {
  const pdf = await buildPDF(rootEl, opts);

  const blob = pdf.output('blob') as Blob;
  if (!blob || blob.size === 0) {
    if (popupWindow && !popupWindow.closed) {
      try { popupWindow.close(); } catch { /* noop */ }
    }
    throw new Error('PDF gerado está vazio (canvas pode ter estourado o limite).');
  }

  downloadBlob(blob, filename, popupWindow);

  const ab = pdf.output('arraybuffer') as ArrayBuffer;
  const u8 = new Uint8Array(ab);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode(...u8.subarray(i, i + chunk));
  }
  return { blob, base64: btoa(bin) };
}

/**
 * Devolve apenas base64 (sem prefixo) para reutilização em fluxos de assinatura/exportação.
 */
export async function sectionedPDFToBase64(
  rootEl: HTMLElement,
  opts: ExportOpts = {},
): Promise<string> {
  const pdf = await buildPDF(rootEl, opts);
  const ab = pdf.output('arraybuffer') as ArrayBuffer;
  const u8 = new Uint8Array(ab);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode(...u8.subarray(i, i + chunk));
  }
  return btoa(bin);
}

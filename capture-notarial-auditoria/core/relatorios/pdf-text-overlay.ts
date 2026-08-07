/**
 * Camada de texto invisível sobre o PDF rasterizado.
 *
 * O laudo é exportado como imagem (html2canvas) para preservar 100% da
 * fidelidade visual. Para que o PDF resultante ainda seja pesquisável
 * (Ctrl+F, cópia de texto), sobrepomos uma camada invisível de jsPDF.text
 * com `renderingMode: 'invisible'` posicionada na mesma coordenada do glifo
 * visível.
 *
 * Mesma técnica usada pelo PDF.js / Google Docs export.
 */

export interface OverlayTextItem {
  /** Texto da linha. */
  text: string;
  /** Posição X em CSS pixels relativa ao topo-esquerda da seção. */
  xPx: number;
  /** Posição Y (baseline aproximada — topo do bloco) em CSS pixels. */
  yPx: number;
  /** Tamanho da fonte em CSS pixels. */
  fontSizePx: number;
}

const SKIP_TAGS = new Set([
  'SCRIPT',
  'STYLE',
  'NOSCRIPT',
  'SVG',
  'CANVAS',
  'IMG',
  'PICTURE',
  'VIDEO',
  'AUDIO',
  'IFRAME',
]);

function isElementVisible(el: Element): boolean {
  const cs = window.getComputedStyle(el);
  if (cs.visibility === 'hidden' || cs.display === 'none' || cs.opacity === '0') {
    return false;
  }
  if (el.getAttribute('aria-hidden') === 'true') return false;
  return true;
}

/**
 * Percorre os nós de texto visíveis dentro da seção e devolve uma lista de
 * itens com coordenadas relativas ao topo-esquerda da seção, prontos para
 * desenhar como camada invisível no PDF.
 */
export function collectTextItems(sectionEl: HTMLElement): OverlayTextItem[] {
  const sectionRect = sectionEl.getBoundingClientRect();
  const items: OverlayTextItem[] = [];

  const walker = document.createTreeWalker(sectionEl, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const text = node.nodeValue;
      if (!text || !text.trim()) return NodeFilter.FILTER_REJECT;
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      if (SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
      // Sobe a árvore conferindo visibilidade.
      let cur: Element | null = parent;
      while (cur && cur !== sectionEl.parentElement) {
        if (!isElementVisible(cur)) return NodeFilter.FILTER_REJECT;
        cur = cur.parentElement;
      }
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  let textNode: Node | null = walker.nextNode();
  while (textNode) {
    const text = (textNode.nodeValue || '').replace(/\s+/g, ' ').trim();
    if (text) {
      const parent = textNode.parentElement as HTMLElement;
      const cs = window.getComputedStyle(parent);
      const fontSizePx = parseFloat(cs.fontSize) || 12;

      try {
        const range = document.createRange();
        range.selectNodeContents(textNode);
        const rects = range.getClientRects();

        if (rects.length > 0) {
          // Particiona o texto pelas linhas visuais (heurística simples:
          // distribui caracteres proporcionalmente à largura de cada rect).
          // Para busca/seleção isso é suficiente — o que importa é o texto
          // existir e estar próximo do glifo correto.
          const totalWidth = Array.from(rects).reduce((s, r) => s + r.width, 0);
          let consumed = 0;
          for (let i = 0; i < rects.length; i++) {
            const r = rects[i];
            if (r.width <= 0 || r.height <= 0) continue;
            const portion =
              i === rects.length - 1
                ? text.length - consumed
                : Math.max(1, Math.round((r.width / totalWidth) * text.length));
            const slice = text.slice(consumed, consumed + portion);
            consumed += portion;
            if (!slice.trim()) continue;
            items.push({
              text: slice,
              xPx: r.left - sectionRect.left,
              yPx: r.top - sectionRect.top,
              fontSizePx,
            });
          }
        } else {
          const r = parent.getBoundingClientRect();
          items.push({
            text,
            xPx: r.left - sectionRect.left,
            yPx: r.top - sectionRect.top,
            fontSizePx,
          });
        }
      } catch {
        /* nó destacado durante captura — ignora */
      }
    }
    textNode = walker.nextNode();
  }

  return items;
}

/**
 * Desenha itens de texto como camada invisível no PDF, mapeando CSS pixels
 * → mm via `mmPerPxCss`. Os itens são filtrados pela faixa Y atualmente
 * desenhada (útil para seções fatiadas em várias páginas).
 *
 * @param pdf instância jsPDF
 * @param items itens coletados via `collectTextItems`
 * @param mmPerPxCss escala CSS px → mm (USABLE_WIDTH_MM / sectionWidthCss)
 * @param offsetXMm posição X do screenshot na página (mm)
 * @param offsetYMm posição Y do topo do screenshot na página (mm)
 * @param sliceTopPx início (em CSS px da seção) da fatia atual; itens
 *                   antes disso são ignorados
 * @param sliceBottomPx fim (em CSS px da seção) da fatia atual; itens
 *                      depois disso são ignorados
 */
export function drawInvisibleTextLayer(
  pdf: any,
  items: OverlayTextItem[],
  mmPerPxCss: number,
  offsetXMm: number,
  offsetYMm: number,
  sliceTopPx = 0,
  sliceBottomPx = Number.POSITIVE_INFINITY,
): void {
  if (!items.length) return;

  // Conversão px → pt (1 pt = 0.352778 mm).
  const MM_PER_PT = 25.4 / 72;

  pdf.setFont('helvetica', 'normal');
  pdf.setTextColor(0, 0, 0);

  for (const item of items) {
    if (item.yPx < sliceTopPx || item.yPx >= sliceBottomPx) continue;
    if (!item.text) continue;

    // Coordenadas finais na página, em mm.
    const xMm = offsetXMm + item.xPx * mmPerPxCss;
    // jsPDF.text usa baseline por padrão. Ajustamos somando ~0.8 da altura
    // da fonte para descer do topo do bloco até a baseline aproximada.
    const lineHeightMm = item.fontSizePx * mmPerPxCss;
    const yMm = offsetYMm + (item.yPx - sliceTopPx) * mmPerPxCss + lineHeightMm * 0.8;

    const fontSizePt = (item.fontSizePx * mmPerPxCss) / MM_PER_PT;
    if (fontSizePt < 1 || fontSizePt > 200) continue;

    pdf.setFontSize(fontSizePt);

    try {
      // `renderingMode: 'invisible'` (modo 3) — texto entra no fluxo de
      // pesquisa/seleção mas não pinta pixels sobre o screenshot.
      pdf.text(item.text, xMm, yMm, {
        renderingMode: 'invisible',
        baseline: 'alphabetic',
      } as any);
    } catch {
      /* alguns caracteres podem falhar no WinAnsi; ignora silenciosamente */
    }
  }
}

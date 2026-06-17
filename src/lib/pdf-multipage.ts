/**
 * PDF Multipágina — Trace Capture / Ata Nível 1
 *
 * Renderiza seções marcadas com [data-pdf-section] do `reportRef`, paginando
 * conforme cabem em A4. Trata o screenshot da URL como seção própria,
 * fatiando-o em múltiplas páginas quando for muito alto.
 *
 * Antes: o report inteiro era rasterizado e desenhado na altura natural na
 * página 1 — qualquer conteúdo abaixo de ~A4 era cortado.
 */
import type { EvidenceRecord } from './trace-capture';
import { downloadPdfWithSelfHash } from './pdf-self-hash';

const A4_WIDTH_MM = 210;
const A4_HEIGHT_MM = 297;
const MARGIN_MM = 10;
const FOOTER_MM = 8;
const SECTION_GAP_MM = 4;
const USABLE_WIDTH_MM = A4_WIDTH_MM - MARGIN_MM * 2;
const USABLE_HEIGHT_MM = A4_HEIGHT_MM - MARGIN_MM * 2 - FOOTER_MM;

async function loadImage(dataUrl: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('Falha ao carregar screenshot'));
    img.src = dataUrl;
  });
}

/**
 * Detecta linhas "seguras" do screenshot pra corte (gutters quase brancos
 * entre cards). Retorna Uint8Array com 1 nas linhas onde >= 98% dos pixels
 * têm luminância >= 240. Em caso de erro (CORS/OOM) retorna null e o
 * slicing degrada graciosamente pro modo antigo.
 */
function computeSafeRows(img: HTMLImageElement): Uint8Array | null {
  try {
    const W = img.width;
    const H = img.height;
    // Downsample horizontal pra reduzir custo: amostra até 200 colunas.
    const sampleCols = Math.min(200, W);
    const canvas = document.createElement('canvas');
    canvas.width = sampleCols;
    canvas.height = H;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return null;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, sampleCols, H);
    ctx.drawImage(img, 0, 0, sampleCols, H);
    const data = ctx.getImageData(0, 0, sampleCols, H).data;
    const safe = new Uint8Array(H);
    const threshold = Math.floor(sampleCols * 0.98);
    for (let y = 0; y < H; y++) {
      let whiteCount = 0;
      const rowStart = y * sampleCols * 4;
      for (let x = 0; x < sampleCols; x++) {
        const i = rowStart + x * 4;
        const r = data[i], g = data[i + 1], b = data[i + 2];
        // luminância aproximada
        const lum = (r * 299 + g * 587 + b * 114) / 1000;
        if (lum >= 240) whiteCount++;
      }
      safe[y] = whiteCount >= threshold ? 1 : 0;
    }
    return safe;
  } catch {
    return null;
  }
}

/**
 * Procura uma linha segura para corte, partindo de `idealEnd` e indo PARA TRÁS
 * até `idealEnd - windowPx`. Retorna idealEnd se nada for achado.
 */
function findSnapPoint(
  safe: Uint8Array,
  start: number,
  idealEnd: number,
  windowPx: number,
): number {
  const min = Math.max(start + 1, idealEnd - windowPx);
  for (let y = idealEnd; y >= min; y--) {
    if (safe[y] === 1) return y;
  }
  return idealEnd;
}

export async function exportEvidencePDF(
  reportElement: HTMLElement,
  record: EvidenceRecord,
  filename: string,
  popup?: Window | null,
): Promise<void> {
  const [{ default: html2canvas }, { default: jsPDF }] = await Promise.all([
    import('html2canvas'),
    import('jspdf'),
  ]);

  const pdf = new jsPDF('p', 'mm', 'a4');

  // Resumo para o Juízo (bloco vetorial em linguagem leiga, no topo da página 1)
  const { drawResumoJuizoPDF } = await import('./resumo-juizo-pdf');
  const resumoNextY = drawResumoJuizoPDF(
    pdf,
    {
      objeto: `URL: ${record.url}`,
      sha256: record.hash,
      capturadoEm: record.capturedAtUTC,
      responsavel: 'Coleta automatizada Trace Hub',
      ipColetor: record.ip,
      verificacaoUrl: `${typeof window !== 'undefined' ? window.location.origin : ''}/verificar-evidencia?hash=${record.hash}`,
    },
    { x: MARGIN_MM, y: MARGIN_MM, width: USABLE_WIDTH_MM },
  );

  // Coleta as seções marcadas; se nenhuma, usa o próprio reportElement como única seção.
  const marked = Array.from(
    reportElement.querySelectorAll<HTMLElement>('[data-pdf-section]'),
  );
  const sections: HTMLElement[] = marked.length > 0 ? marked : [reportElement];

  let currentY = resumoNextY;
  let currentPage = 1;

  const addFooter = (pageNum: number, totalPages: number) => {
    pdf.setFontSize(8);
    pdf.setTextColor(120);
    pdf.text(
      `Trace Hub · ISO 27037 · ${record.id.slice(0, 8)}`,
      MARGIN_MM,
      A4_HEIGHT_MM - 5,
    );
    pdf.text(
      `Página ${pageNum} de ${totalPages || '…'}`,
      A4_WIDTH_MM - MARGIN_MM,
      A4_HEIGHT_MM - 5,
      { align: 'right' },
    );
  };

  const newPage = () => {
    addFooter(currentPage, 0);
    pdf.addPage();
    currentPage += 1;
    currentY = MARGIN_MM;
  };

  // Renderiza cada seção; abre nova página quando não cabe.
  for (const section of sections) {
    const canvas = await html2canvas(section, {
      scale: 2,
      backgroundColor: '#ffffff',
      useCORS: true,
      logging: false,
    });
    const widthPx = canvas.width;
    const heightPx = canvas.height;
    const heightMM = (heightPx * USABLE_WIDTH_MM) / widthPx;

    // Se a seção é maior que uma página inteira, precisamos fatiá-la também.
    if (heightMM > USABLE_HEIGHT_MM) {
      const pxPerMM = widthPx / USABLE_WIDTH_MM;
      let drawnPx = 0;
      while (drawnPx < heightPx) {
        // Espaço disponível na página atual
        const remainingMM = A4_HEIGHT_MM - MARGIN_MM - FOOTER_MM - currentY;
        if (remainingMM < 20) {
          newPage();
        }
        const availMM = A4_HEIGHT_MM - MARGIN_MM - FOOTER_MM - currentY;
        const sliceMM = Math.min(availMM, (heightPx - drawnPx) / pxPerMM);
        const slicePx = Math.min(sliceMM * pxPerMM, heightPx - drawnPx);

        const sliceCanvas = document.createElement('canvas');
        sliceCanvas.width = widthPx;
        sliceCanvas.height = slicePx;
        const sctx = sliceCanvas.getContext('2d')!;
        sctx.fillStyle = '#fff';
        sctx.fillRect(0, 0, sliceCanvas.width, sliceCanvas.height);
        sctx.drawImage(canvas, 0, -drawnPx);
        const sliceData = sliceCanvas.toDataURL('image/jpeg', 0.88);
        const sliceHeightMM = (slicePx * USABLE_WIDTH_MM) / widthPx;
        pdf.addImage(sliceData, 'JPEG', MARGIN_MM, currentY, USABLE_WIDTH_MM, sliceHeightMM);
        currentY += sliceHeightMM + SECTION_GAP_MM;
        drawnPx += slicePx;
        if (drawnPx < heightPx) newPage();
      }
    } else {
      // Cabe? Se não, vai pra próxima página.
      if (currentY + heightMM > A4_HEIGHT_MM - MARGIN_MM - FOOTER_MM && currentY > MARGIN_MM) {
        newPage();
      }
      const imgData = canvas.toDataURL('image/jpeg', 0.92);
      pdf.addImage(imgData, 'JPEG', MARGIN_MM, currentY, USABLE_WIDTH_MM, heightMM);
      currentY += heightMM + SECTION_GAP_MM;
    }
  }

  // Screenshot real, se houver e não estiver já no report.
  if (record.screenshotDataUrl && !reportElement.querySelector('[data-pdf-screenshot-included]')) {
    const screenshotImg = await loadImage(record.screenshotDataUrl);
    const screenshotHeightMM = (screenshotImg.height * USABLE_WIDTH_MM) / screenshotImg.width;
    const pxPerMM = screenshotImg.width / USABLE_WIDTH_MM;

    // Sempre começa numa página dedicada para o screenshot.
    newPage();
    pdf.setFontSize(9);
    pdf.setTextColor(16, 185, 129);
    pdf.text('SCREENSHOT DA URL CAPTURADA', MARGIN_MM, currentY + 4);
    currentY += 8;

    // Pré-calcula linhas seguras pra corte (gutters brancos entre cards).
    const safeRows = computeSafeRows(screenshotImg);

    let drawnPx = 0;
    const totalPx = screenshotImg.height;
    while (drawnPx < totalPx) {
      const availMM = A4_HEIGHT_MM - MARGIN_MM - FOOTER_MM - currentY;
      if (availMM < 30) {
        newPage();
        continue;
      }
      const availPx = availMM * pxPerMM;
      const remainingPx = totalPx - drawnPx;
      let endPx = drawnPx + Math.min(availPx, remainingPx);
      const isLast = endPx >= totalPx;

      // Snap pra linha branca se não for a última fatia e tivermos safeRows.
      if (!isLast && safeRows) {
        const idealLen = endPx - drawnPx;
        // Janela de busca: até 18% da fatia ou 220px, o que for menor.
        // Garante fatia mínima de 30% pra não criar muitas páginas vazias.
        const windowPx = Math.min(Math.floor(idealLen * 0.18), 220);
        const minLen = Math.floor(idealLen * 0.3);
        const snapped = findSnapPoint(
          safeRows,
          drawnPx + minLen,
          Math.floor(endPx),
          windowPx,
        );
        if (snapped < endPx) endPx = snapped;
      }

      const slicePx = endPx - drawnPx;
      const sliceCanvas = document.createElement('canvas');
      sliceCanvas.width = screenshotImg.width;
      sliceCanvas.height = slicePx;
      const ctx = sliceCanvas.getContext('2d')!;
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, sliceCanvas.width, sliceCanvas.height);
      ctx.drawImage(screenshotImg, 0, -drawnPx);
      const sliceData = sliceCanvas.toDataURL('image/jpeg', 0.85);
      const sliceHeightMM = (slicePx * USABLE_WIDTH_MM) / screenshotImg.width;
      pdf.addImage(sliceData, 'JPEG', MARGIN_MM, currentY, USABLE_WIDTH_MM, sliceHeightMM);
      currentY += sliceHeightMM;
      drawnPx = endPx;
      if (drawnPx < totalPx) newPage();
    }
  }

  // Footer da última página
  addFooter(currentPage, currentPage);

  // Atualiza footer de todas as páginas com total real
  const finalTotal = currentPage;
  for (let i = 1; i <= finalTotal; i++) {
    pdf.setPage(i);
    pdf.setFillColor(255, 255, 255);
    pdf.rect(A4_WIDTH_MM - MARGIN_MM - 40, A4_HEIGHT_MM - 9, 40, 6, 'F');
    pdf.setFontSize(8);
    pdf.setTextColor(120);
    pdf.text(
      `Página ${i} de ${finalTotal}`,
      A4_WIDTH_MM - MARGIN_MM,
      A4_HEIGHT_MM - 5,
      { align: 'right' },
    );
  }

  await downloadPdfWithSelfHash(pdf.output('blob') as Blob, filename, popup);
}

/**
 * Garante que as fontes cartoriais (Cinzel, EB Garamond, JetBrains Mono)
 * estejam realmente carregadas antes de gerar o PDF/PNG do laudo.
 *
 * Sem isso, o html2canvas tira print com fallback serif e calcula altura
 * errada, gerando canvas gigante que estoura o limite no mobile.
 */

let injected = false;
let readyPromise: Promise<void> | null = null;

const FONT_HREF =
  'https://fonts.googleapis.com/css2?' +
  'family=Cinzel:wght@400;700&' +
  'family=EB+Garamond:ital,wght@0,400;0,600;1,400&' +
  'family=JetBrains+Mono:wght@400;600&display=swap';

const REQUIRED: Array<[string, string]> = [
  ['400 12px "Cinzel"', 'Cinzel'],
  ['700 12px "Cinzel"', 'Cinzel'],
  ['400 12px "EB Garamond"', 'EB Garamond'],
  ['600 12px "EB Garamond"', 'EB Garamond'],
  ['400 12px "JetBrains Mono"', 'JetBrains Mono'],
];

function injectStylesheet() {
  if (injected || typeof document === 'undefined') return;
  injected = true;

  // Preconnect para acelerar handshake
  const pre1 = document.createElement('link');
  pre1.rel = 'preconnect';
  pre1.href = 'https://fonts.googleapis.com';
  document.head.appendChild(pre1);

  const pre2 = document.createElement('link');
  pre2.rel = 'preconnect';
  pre2.href = 'https://fonts.gstatic.com';
  pre2.crossOrigin = 'anonymous';
  document.head.appendChild(pre2);

  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = FONT_HREF;
  link.setAttribute('data-forensic-fonts', 'true');
  document.head.appendChild(link);
}

export async function ensureForensicFontsLoaded(timeoutMs = 3000): Promise<void> {
  if (typeof document === 'undefined') return;
  if (readyPromise) return readyPromise;

  injectStylesheet();

  readyPromise = (async () => {
    try {
      const fontsApi: any = (document as any).fonts;
      if (!fontsApi || typeof fontsApi.load !== 'function') {
        // Sem FontFace API — espera fixa pequena e segue
        await new Promise((r) => setTimeout(r, 600));
        return;
      }

      const loaders = REQUIRED.map(([spec]) =>
        fontsApi.load(spec).catch(() => null),
      );

      await Promise.race([
        Promise.all([fontsApi.ready, ...loaders]),
        new Promise((resolve) => setTimeout(resolve, timeoutMs)),
      ]);
    } catch {
      /* não bloqueia o export por causa de fontes */
    }
  })();

  return readyPromise;
}

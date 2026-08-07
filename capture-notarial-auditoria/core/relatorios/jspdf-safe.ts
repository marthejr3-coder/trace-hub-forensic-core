/**
 * Adaptador resiliente para jsPDF + jspdf-autotable.
 *
 * Motivo: `jspdf-autotable` publica a entrada principal em CommonJS e o
 * `jspdf` em UMD. Um `import default` desses pacotes pode perder o interop
 * no bundle de produção, gerando erros do tipo
 * `(0 , X.default) is not a function` no momento de exportar o PDF.
 *
 * Aqui usamos imports de *namespace* (sempre estáveis no interop) e
 * resolvemos a função/construtor real em tempo de execução.
 */
import * as jsPDFModule from 'jspdf';
import * as autoTableModule from 'jspdf-autotable';
import * as html2canvasModule from 'html2canvas';

type AnyRecord = Record<string, any>;

/** Retorna o construtor do jsPDF, aceitando todas as formas de export. */
export function getJsPDF(): any {
  const mod = jsPDFModule as unknown as AnyRecord;
  const candidates = [
    mod?.jsPDF,
    mod?.default?.jsPDF,
    mod?.default,
    mod,
  ];
  for (const c of candidates) {
    if (typeof c === 'function') return c;
  }
  throw new Error('jsPDF não pôde ser carregado (export inesperado).');
}

/** Instancia um documento jsPDF com os mesmos argumentos do construtor. */
export function createPdf(...args: any[]): any {
  const Ctor = getJsPDF();
  return new Ctor(...args);
}

let pluginApplied = false;

/**
 * Desenha uma tabela. Substitui 1:1 `autoTable(doc, options)`.
 */
export function drawTable(doc: any, options: any): void {
  const mod = autoTableModule as unknown as AnyRecord;

  const fn =
    typeof mod?.default === 'function'
      ? mod.default
      : typeof mod?.autoTable === 'function'
        ? mod.autoTable
        : null;

  if (fn) {
    fn(doc, options);
    return;
  }

  // Fallback: aplica o plugin e usa o método anexado ao documento.
  if (!pluginApplied && typeof mod?.applyPlugin === 'function') {
    try {
      mod.applyPlugin(getJsPDF());
      pluginApplied = true;
    } catch {
      /* ignora — tenta o método já anexado abaixo */
    }
  }

  if (typeof doc?.autoTable === 'function') {
    doc.autoTable(options);
    return;
  }

  throw new Error('jspdf-autotable não pôde ser carregado (export inesperado).');
}

/** Retorna a função html2canvas (mesmo problema de interop do default CJS). */
export function getHtml2Canvas(): any {
  const mod = html2canvasModule as unknown as AnyRecord;
  const candidates = [mod?.default, mod?.html2canvas, mod];
  for (const c of candidates) {
    if (typeof c === 'function') return c;
  }
  throw new Error('html2canvas não pôde ser carregado (export inesperado).');
}

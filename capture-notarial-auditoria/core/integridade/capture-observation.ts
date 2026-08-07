/**
 * Escopo de observação da gravação lacrada + sensores que funcionam
 * mesmo quando o alvo está numa aba EXTERNA (cross-origin).
 *
 * Motivação forense: a cadeia de hash do DOM (DomHashChain) só consegue
 * observar documentos same-origin (o proxy lacrado do Trace Hub). Quando o
 * operador compartilha uma aba/janela/monitor de outra origem — por exemplo
 * WhatsApp Web já logado — nenhum código web consegue ler aquele DOM. Nesse
 * cenário a gravação é PIXEL-ONLY: a plataforma atesta o arquivo de vídeo,
 * mas NÃO atesta a fidelidade do conteúdo exibido (art. 411, II do CPC —
 * responsabilidade do exibidor).
 *
 * Este módulo:
 *  1. classifica o escopo (observed × pixel_only) a partir da track;
 *  2. vigia a superfície capturada (mudança de dimensões = forte indício de
 *     DevTools/inspetor aberto na aba alvo; troca de superfície no meio da
 *     coleta);
 *  3. mantém uma cadeia de hash de frames amostrados (1 fps), permitindo
 *     detectar edição posterior do arquivo de vídeo.
 */
import { sha256Hex, utcNow } from './hash';

export type ObservationScope = 'observed' | 'pixel_only';

export interface ObservationScopeInfo {
  scope: ObservationScope;
  /** 'browser' | 'window' | 'monitor' | 'unknown' */
  display_surface: string;
  /** true quando o DOM do alvo é observável (proxy same-origin). */
  dom_observable: boolean;
  initial_frame_size: { width: number; height: number } | null;
  label: string;
  declared_at: string;
}

export interface SurfaceEvent {
  timestamp: string;
  kind: 'captured_surface_resize' | 'surface_switched' | 'surface_ended';
  details: Record<string, unknown>;
}

const SCOPE_LABEL: Record<ObservationScope, string> = {
  observed:
    'OBSERVADA — alvo carregado no ambiente lacrado do Trace Hub: cadeia de hash do DOM ativa, mutações registradas e ambiente monitorado.',
  pixel_only:
    'NÃO OBSERVADA (pixel-only) — superfície externa compartilhada pelo operador: a plataforma atesta o arquivo de vídeo e os horários, mas NÃO observou o DOM do conteúdo exibido.',
};

export function classifyObservationScope(
  track: MediaStreamTrack | undefined,
  domObservable: boolean,
): ObservationScopeInfo {
  const s = (track?.getSettings?.() ?? {}) as MediaTrackSettings & { displaySurface?: string };
  const display_surface = s.displaySurface ?? 'unknown';
  // Só é "observada" quando o DOM do alvo é lido pela cadeia de hash.
  const scope: ObservationScope = domObservable ? 'observed' : 'pixel_only';
  return {
    scope,
    display_surface,
    dom_observable: domObservable,
    initial_frame_size:
      s.width && s.height ? { width: Number(s.width), height: Number(s.height) } : null,
    label: SCOPE_LABEL[scope],
    declared_at: utcNow(),
  };
}

/** Aviso jurídico que vai para a UI e para o PDF. */
export const PIXEL_ONLY_WARNING =
  'O conteúdo exibido nesta gravação NÃO foi observado pela cadeia de integridade da plataforma. ' +
  'O Trace Hub atesta o arquivo de vídeo, os horários e os hashes; a fidelidade do que a tela exibia ' +
  'é de responsabilidade do exibidor (CPC, art. 411, II). Alterações feitas no navegador do operador ' +
  '(por exemplo edição de HTML via DevTools na aba compartilhada) não são detectáveis por código web ' +
  'em origem distinta. Para coleta com DOM observado em site autenticado, utilize o Trace Hub Desktop.';

/**
 * Vigia a superfície compartilhada. Abrir o DevTools dentro da aba gravada
 * encolhe o viewport dela e altera as dimensões dos frames entregues.
 */
export class CaptureSurfaceWatcher {
  private timer: number | null = null;
  private last: { width: number; height: number } | null = null;
  private lastLabel: string | null = null;
  private events: SurfaceEvent[] = [];
  private stopped = false;

  constructor(
    private readonly track: MediaStreamTrack,
    private readonly opts: {
      intervalMs?: number;
      /** Variação mínima (px) para considerar redimensionamento relevante. */
      threshold?: number;
      onEvent?: (ev: SurfaceEvent) => void;
    } = {},
  ) {}

  private emit(kind: SurfaceEvent['kind'], details: Record<string, unknown>) {
    if (this.stopped) return;
    const ev: SurfaceEvent = { timestamp: utcNow(), kind, details };
    this.events.push(ev);
    try {
      this.opts.onEvent?.(ev);
    } catch {
      /* noop */
    }
  }

  private check() {
    const s = (this.track.getSettings?.() ?? {}) as MediaTrackSettings & { displaySurface?: string };
    const width = Number(s.width) || 0;
    const height = Number(s.height) || 0;
    const label = this.track.label ?? null;

    if (this.lastLabel !== null && label !== this.lastLabel) {
      this.emit('surface_switched', { from: this.lastLabel, to: label });
    }
    this.lastLabel = label;

    if (width > 0 && height > 0) {
      if (this.last) {
        const threshold = this.opts.threshold ?? 24;
        const dw = Math.abs(width - this.last.width);
        const dh = Math.abs(height - this.last.height);
        if (dw > threshold || dh > threshold) {
          this.emit('captured_surface_resize', {
            from: { ...this.last },
            to: { width, height },
            delta: { width: dw, height: dh },
            threshold,
            interpretation:
              'A superfície capturada mudou de tamanho durante a coleta. Em aba de navegador isso ocorre tipicamente quando o inspetor/DevTools é aberto ou acoplado, quando a janela é redimensionada ou quando o zoom muda.',
          });
        }
      }
      this.last = { width, height };
    }
  }

  start() {
    this.stopped = false;
    this.check();
    this.timer = window.setInterval(() => this.check(), this.opts.intervalMs ?? 1000);
    try {
      this.track.addEventListener('ended', () => this.emit('surface_ended', { label: this.track.label }));
    } catch {
      /* noop */
    }
  }

  stop() {
    this.stopped = true;
    if (this.timer !== null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
  }

  getEvents(): SurfaceEvent[] {
    return [...this.events];
  }
}

export interface FrameChainLink {
  seq: number;
  timestamp: string;
  frame_sha256: string;
  prev_hash: string;
  chain_hash: string;
  width: number;
  height: number;
}

export const FRAME_GENESIS = '0'.repeat(64);

/**
 * Cadeia de hash de frames amostrados: 1 quadro por segundo é reduzido,
 * serializado em PNG e encadeado. Permite demonstrar, depois, que o arquivo
 * de vídeo entregue corresponde aos quadros observados na coleta.
 */
export class FrameHashChain {
  private links: FrameChainLink[] = [];
  private timer: number | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private busy = false;

  constructor(
    private readonly video: HTMLVideoElement,
    private readonly opts: { intervalMs?: number; maxWidth?: number; onLink?: (l: FrameChainLink) => void } = {},
  ) {}

  private get prevHash(): string {
    return this.links.length === 0 ? FRAME_GENESIS : this.links[this.links.length - 1].chain_hash;
  }

  private async sample() {
    if (this.busy) return;
    const vw = this.video.videoWidth;
    const vh = this.video.videoHeight;
    if (!vw || !vh) return;
    this.busy = true;
    try {
      const maxW = this.opts.maxWidth ?? 480;
      const scale = Math.min(1, maxW / vw);
      const w = Math.max(2, Math.round(vw * scale));
      const h = Math.max(2, Math.round(vh * scale));
      if (!this.canvas) this.canvas = document.createElement('canvas');
      this.canvas.width = w;
      this.canvas.height = h;
      const ctx = this.canvas.getContext('2d', { alpha: false });
      if (!ctx) return;
      ctx.drawImage(this.video, 0, 0, w, h);
      const data = ctx.getImageData(0, 0, w, h).data;
      const frame_sha256 = await sha256Hex(new Uint8Array(data.buffer.slice(0)));
      const timestamp = utcNow();
      const prev_hash = this.prevHash;
      const chain_hash = await sha256Hex(`${prev_hash}|${frame_sha256}|${timestamp}`);
      const link: FrameChainLink = {
        seq: this.links.length + 1,
        timestamp,
        frame_sha256,
        prev_hash,
        chain_hash,
        width: vw,
        height: vh,
      };
      this.links.push(link);
      try {
        this.opts.onLink?.(link);
      } catch {
        /* noop */
      }
    } catch {
      /* noop */
    } finally {
      this.busy = false;
    }
  }

  start() {
    void this.sample();
    this.timer = window.setInterval(() => void this.sample(), this.opts.intervalMs ?? 1000);
  }

  stop() {
    if (this.timer !== null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
    // Libera o canvas de amostragem (evita retenção de memória da aba).
    if (this.canvas) {
      this.canvas.width = 0;
      this.canvas.height = 0;
      this.canvas = null;
    }
  }


  getLinks(): FrameChainLink[] {
    return [...this.links];
  }

  get finalHash(): string | null {
    return this.links.length === 0 ? null : this.links[this.links.length - 1].chain_hash;
  }
}

/** Verificação offline da cadeia de frames (usada pelo verificador público). */
export async function verifyFrameChain(
  links: FrameChainLink[],
): Promise<{ valid: boolean; brokenAt: number | null; count: number }> {
  let prev = FRAME_GENESIS;
  for (const l of links) {
    if (l.prev_hash !== prev) return { valid: false, brokenAt: l.seq, count: links.length };
    const expected = await sha256Hex(`${l.prev_hash}|${l.frame_sha256}|${l.timestamp}`);
    if (expected !== l.chain_hash) return { valid: false, brokenAt: l.seq, count: links.length };
    prev = l.chain_hash;
  }
  return { valid: true, brokenAt: null, count: links.length };
}

/**
 * Requisitos 2, 3 e 4 — Hash chain contínua do DOM + MutationObserver.
 *
 * A cada intervalo (e a cada mutação relevante) tiramos um snapshot
 * normalizado do documento observado, calculamos SHA-256 e encadeamos:
 *
 *   H(n) = SHA-256( H(n-1) || dom_sha256 || timestamp_utc )
 *
 * O snapshot é normalizado para eliminar ruído volátil (nonces, ids
 * aleatórios, timestamps de anúncios) e garantir reprodutibilidade.
 */
import { sha256Hex, utcNow } from './hash';

export const DOM_GENESIS = '0'.repeat(64);

export interface DomChainLink {
  seq: number;
  timestamp: string;
  dom_sha256: string;
  prev_hash: string;
  chain_hash: string;
  /** Bytes do HTML normalizado (não persiste o conteúdo, só o tamanho). */
  normalized_length: number;
  trigger: 'interval' | 'mutation' | 'manual' | 'artifact';
  url?: string | null;
}

export interface MutationRecord0 {
  timestamp: string;
  type: 'childList' | 'attributes' | 'characterData';
  target: string;
  added: number;
  removed: number;
  attribute?: string | null;
}

/** Remove ruído volátil do HTML antes de hashear. */
export function normalizeHtml(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '<script/>')
    .replace(/\snonce="[^"]*"/gi, '')
    .replace(/\sdata-reactid="[^"]*"/gi, '')
    .replace(/\sdata-testid="[^"]*"/gi, '')
    .replace(/\bid="(?:[a-z]*[-_]?)?[0-9a-f]{8,}"/gi, 'id="__volatile__"')
    .replace(/\b\d{13}\b/g, '__epoch_ms__')
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{2,}/g, '\n')
    .trim();
}

export async function hashDomSnapshot(html: string): Promise<{ dom_sha256: string; normalized_length: number }> {
  const normalized = normalizeHtml(html);
  return { dom_sha256: await sha256Hex(normalized), normalized_length: normalized.length };
}

export class DomHashChain {
  private links: DomChainLink[] = [];
  private mutations: MutationRecord0[] = [];
  private observer: MutationObserver | null = null;
  private timer: number | null = null;
  private lastDomHash: string | null = null;
  private mutationSnapshotTimer: number | null = null;
  private lastMutationSnapshotAt = 0;
  private snapshotInFlight = false;

  constructor(
    private readonly opts: {
      /** Documento a observar. Se ausente, retorna null (sem fallback para o document do app). */
      getDocument?: () => Document | null;
      intervalMs?: number;
      /** Intervalo mínimo entre snapshots disparados por mutação. Padrão 5s. */
      mutationThrottleMs?: number;
      onLink?: (link: DomChainLink) => void;
      onMutation?: (m: MutationRecord0) => void;
    } = {},
  ) {}

  private doc(): Document | null {
    try {
      // Sem fallback para `document`: se o observador não conseguir enxergar
      // o iframe alvo (cross-origin), NUNCA cai no document do próprio app,
      // pois cada evento logado atualiza o React → provoca mutação DOM →
      // dispara novo snapshot → loop infinito de sealed-session-event.
      return this.opts.getDocument ? this.opts.getDocument() : null;
    } catch {
      return null;
    }
  }

  get prevHash(): string {
    return this.links.length === 0 ? DOM_GENESIS : this.links[this.links.length - 1].chain_hash;
  }

  /** Registra um elo. Retorna null se o DOM está inacessível (cross-origin). */
  async snapshot(trigger: DomChainLink['trigger'] = 'manual'): Promise<DomChainLink | null> {
    if (this.snapshotInFlight) return null;
    this.snapshotInFlight = true;
    try {
    const d = this.doc();
    if (!d?.documentElement) return null;
    let html: string;
    try {
      html = d.documentElement.outerHTML;
    } catch {
      return null;
    }
    const { dom_sha256, normalized_length } = await hashDomSnapshot(html);
    // Deduplica snapshots com hash idêntico, independente do trigger.
    if (dom_sha256 === this.lastDomHash) return null;
    this.lastDomHash = dom_sha256;
    const timestamp = utcNow();
    const prev_hash = this.prevHash;
    const chain_hash = await sha256Hex(`${prev_hash}|${dom_sha256}|${timestamp}`);
    const link: DomChainLink = {
      seq: this.links.length + 1,
      timestamp,
      dom_sha256,
      prev_hash,
      chain_hash,
      normalized_length,
      trigger,
      url: (() => {
        try {
          return d.location?.href ?? null;
        } catch {
          return null;
        }
      })(),
    };
    this.links.push(link);
    try {
      this.opts.onLink?.(link);
    } catch {
      /* noop */
    }
    return link;
    } finally {
      this.snapshotInFlight = false;
    }
  }

  private scheduleMutationSnapshot() {
    const throttleMs = this.opts.mutationThrottleMs ?? 5000;
    if (this.mutationSnapshotTimer !== null) return;
    const now = Date.now();
    const elapsed = now - this.lastMutationSnapshotAt;
    const wait = elapsed >= throttleMs ? 0 : throttleMs - elapsed;
    this.mutationSnapshotTimer = window.setTimeout(() => {
      this.mutationSnapshotTimer = null;
      this.lastMutationSnapshotAt = Date.now();
      void this.snapshot('mutation');
    }, wait);
  }

  start() {
    const intervalMs = this.opts.intervalMs ?? 5000;
    void this.snapshot('manual');
    this.timer = window.setInterval(() => {
      void this.snapshot('interval');
    }, intervalMs);

    const d = this.doc();
    if (d?.documentElement && typeof MutationObserver !== 'undefined') {
      try {
        this.observer = new MutationObserver((records) => {
          for (const r of records) {
            const m: MutationRecord0 = {
              timestamp: utcNow(),
              type: r.type as MutationRecord0['type'],
              target: (r.target as Element)?.nodeName?.toLowerCase?.() ?? 'unknown',
              added: r.addedNodes?.length ?? 0,
              removed: r.removedNodes?.length ?? 0,
              attribute: r.attributeName ?? null,
            };
            this.mutations.push(m);
            try {
              this.opts.onMutation?.(m);
            } catch {
              /* noop */
            }
          }
          this.scheduleMutationSnapshot();
        });
        this.observer.observe(d.documentElement, {
          childList: true,
          subtree: true,
          attributes: true,
          characterData: true,
        });
      } catch {
        this.observer = null;
      }
    }
  }

  stop() {
    if (this.timer !== null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
    if (this.mutationSnapshotTimer !== null) {
      window.clearTimeout(this.mutationSnapshotTimer);
      this.mutationSnapshotTimer = null;
    }
    try {
      this.observer?.disconnect();
    } catch {
      /* noop */
    }
    this.observer = null;
  }

  getLinks(): DomChainLink[] {
    return [...this.links];
  }

  getMutations(): MutationRecord0[] {
    return [...this.mutations];
  }

  /** Verificação local da cadeia (mesma rotina usada pelo verificador offline). */
  async verify(): Promise<{ valid: boolean; brokenAt: number | null }> {
    let prev = DOM_GENESIS;
    for (const l of this.links) {
      if (l.prev_hash !== prev) return { valid: false, brokenAt: l.seq };
      const expected = await sha256Hex(`${l.prev_hash}|${l.dom_sha256}|${l.timestamp}`);
      if (expected !== l.chain_hash) return { valid: false, brokenAt: l.seq };
      prev = l.chain_hash;
    }
    return { valid: true, brokenAt: null };
  }
}

/** Verifica uma cadeia de DOM exportada (usado no modo verificador offline). */
export async function verifyDomChain(
  links: DomChainLink[],
): Promise<{ valid: boolean; brokenAt: number | null; count: number }> {
  let prev = DOM_GENESIS;
  for (const l of links) {
    if (l.prev_hash !== prev) return { valid: false, brokenAt: l.seq, count: links.length };
    const expected = await sha256Hex(`${l.prev_hash}|${l.dom_sha256}|${l.timestamp}`);
    if (expected !== l.chain_hash) return { valid: false, brokenAt: l.seq, count: links.length };
    prev = l.chain_hash;
  }
  return { valid: true, brokenAt: null, count: links.length };
}

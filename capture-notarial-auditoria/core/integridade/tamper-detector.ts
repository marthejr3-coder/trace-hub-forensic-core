/**
 * Requisito 1 — Detecção de DevTools e ambiente adulterado.
 *
 * Vários sensores simultâneos. Cada detecção gera um evento auditável que é
 * inserido na hash chain da sessão lacrada (event_type = 'tamper') e marca a
 * sessão como environment_tampered.
 *
 * Modos: 'warn' (padrão — apenas registra e alerta) ou 'abort' (registra e
 * chama onAbort para encerrar a captura).
 */
import { utcNow } from './hash';

export type TamperMethod =
  | 'window_dimension_delta'
  | 'debugger_timing_trap'
  | 'console_getter_inspection'
  | 'native_function_override'
  | 'critical_object_mutation'
  | 'headless_context'
  | 'console_api_tampered'
  | 'captured_surface_resize'
  | 'surface_switched'
  | 'tamper_during_recording';

export interface TamperEvent {
  timestamp: string;
  event: 'devtools_detected' | 'environment_tampered' | 'captured_surface_anomaly';
  method: TamperMethod;
  details?: Record<string, unknown>;
}

export interface TamperDetectorOptions {
  mode?: 'warn' | 'abort';
  /** Intervalo do poll de dimensões/traps, em ms. */
  intervalMs?: number;
  onDetect: (event: TamperEvent) => void;
  onAbort?: (event: TamperEvent) => void;
}

const DIMENSION_THRESHOLD = 160;

function nativeSignature(fn: unknown): boolean {
  try {
    return typeof fn === 'function' && /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn));
  } catch {
    return false;
  }
}

export class TamperDetector {
  private timer: number | null = null;
  private stopped = false;
  private fired = new Set<TamperMethod>();
  private readonly mode: 'warn' | 'abort';
  private readonly intervalMs: number;
  private readonly baseline: {
    toStringNative: boolean;
    digestNative: boolean;
    fetchNative: boolean;
    recorderNative: boolean;
    consoleLogNative: boolean;
  };

  constructor(private readonly opts: TamperDetectorOptions) {
    this.mode = opts.mode ?? 'warn';
    this.intervalMs = opts.intervalMs ?? 1500;
    this.baseline = {
      toStringNative: nativeSignature(Function.prototype.toString),
      digestNative: nativeSignature(crypto?.subtle?.digest),
      fetchNative: nativeSignature(window.fetch),
      recorderNative:
        typeof MediaRecorder === 'undefined' ? true : nativeSignature(MediaRecorder.prototype.start),
      consoleLogNative: nativeSignature(console.log),
    };
  }

  private emit(method: TamperMethod, details?: Record<string, unknown>) {
    if (this.stopped) return;
    // Append-only: cada método reporta apenas uma vez por sessão (evita flood).
    if (this.fired.has(method)) return;
    this.fired.add(method);
    const ev: TamperEvent = {
      timestamp: utcNow(),
      event:
        method === 'captured_surface_resize' || method === 'surface_switched'
          ? 'captured_surface_anomaly'
        : method === 'window_dimension_delta' ||
        method === 'debugger_timing_trap' ||
        method === 'console_getter_inspection'
          ? 'devtools_detected'
          : 'environment_tampered',
      method,
      details,
    };
    try {
      this.opts.onDetect(ev);
    } catch {
      /* noop */
    }
    if (this.mode === 'abort') {
      try {
        this.opts.onAbort?.(ev);
      } catch {
        /* noop */
      }
    }
  }

  /**
   * Reporta manualmente um sinal externo (por exemplo anomalia da superfície
   * compartilhada durante a gravação, detectada fora do detector).
   */
  report(method: TamperMethod, details?: Record<string, unknown>) {
    this.emit(method, details);
  }

  /** Sensor 1/2 — deltas entre outer* e inner*. */
  private checkDimensions() {
    const dw = Math.abs(window.outerWidth - window.innerWidth);
    const dh = Math.abs(window.outerHeight - window.innerHeight);
    if (window.outerWidth === 0 || window.outerHeight === 0) return;
    if (dw > DIMENSION_THRESHOLD || dh > DIMENSION_THRESHOLD) {
      this.emit('window_dimension_delta', {
        outer: { width: window.outerWidth, height: window.outerHeight },
        inner: { width: window.innerWidth, height: window.innerHeight },
        delta: { width: dw, height: dh },
        threshold: DIMENSION_THRESHOLD,
      });
    }
  }

  /** Sensor 3 — debugger timing trap. */
  private checkDebuggerTiming() {
    const t0 = performance.now();
    try {
      // eslint-disable-next-line no-debugger
      debugger;
    } catch {
      /* noop */
    }
    const elapsed = performance.now() - t0;
    if (elapsed > 120) {
      this.emit('debugger_timing_trap', { elapsed_ms: Math.round(elapsed) });
    }
  }

  /** Sensor 4 — getter armadilhado: o DevTools inspeciona o objeto logado. */
  private checkConsoleGetter() {
    const probe = {} as Record<string, unknown>;
    let inspected = false;
    Object.defineProperty(probe, 'id', {
      get: () => {
        inspected = true;
        return 'trace-hub-probe';
      },
      configurable: true,
      enumerable: true,
    });
    try {
      console.debug(probe);
      console.clear === undefined; // noop, mantém referência
    } catch {
      /* noop */
    }
    if (inspected) this.emit('console_getter_inspection');
  }

  /** Sensor 5/6 — sobrescrita de funções nativas e objetos críticos. */
  private checkNativeOverrides() {
    const now = {
      toStringNative: nativeSignature(Function.prototype.toString),
      digestNative: nativeSignature(crypto?.subtle?.digest),
      fetchNative: nativeSignature(window.fetch),
      recorderNative:
        typeof MediaRecorder === 'undefined' ? true : nativeSignature(MediaRecorder.prototype.start),
      consoleLogNative: nativeSignature(console.log),
    };
    const changed = Object.entries(now).filter(
      ([k, v]) => this.baseline[k as keyof typeof now] && !v,
    );
    if (changed.length > 0) {
      const keys = changed.map(([k]) => k);
      if (keys.includes('consoleLogNative') && keys.length === 1) {
        this.emit('console_api_tampered', { functions: keys });
      } else if (keys.some((k) => k === 'digestNative' || k === 'fetchNative' || k === 'recorderNative')) {
        this.emit('critical_object_mutation', { functions: keys });
      } else {
        this.emit('native_function_override', { functions: keys });
      }
    }
  }

  /** Sensor 7 — contexto headless/automatizado. */
  private checkHeadless() {
    const nav = navigator as Navigator & { webdriver?: boolean };
    const signals: string[] = [];
    if (nav.webdriver) signals.push('navigator.webdriver');
    if (/headless/i.test(navigator.userAgent)) signals.push('ua_headless');
    if (navigator.languages && navigator.languages.length === 0) signals.push('empty_languages');
    if (navigator.plugins && navigator.plugins.length === 0 && !/mobile|iphone|android/i.test(navigator.userAgent)) {
      signals.push('empty_plugins_desktop');
    }
    if (signals.length > 0) this.emit('headless_context', { signals });
  }

  start() {
    this.stopped = false;
    const tick = () => {
      if (this.stopped) return;
      try {
        this.checkDimensions();
        this.checkNativeOverrides();
        this.checkConsoleGetter();
        this.checkDebuggerTiming();
      } catch {
        /* noop */
      }
    };
    this.checkHeadless();
    tick();
    this.timer = window.setInterval(tick, this.intervalMs);
  }

  stop() {
    this.stopped = true;
    if (this.timer !== null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
  }

  get detectedMethods(): TamperMethod[] {
    return [...this.fired];
  }

  get tampered(): boolean {
    return this.fired.size > 0;
  }
}

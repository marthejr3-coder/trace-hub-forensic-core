// Monitor de nível de áudio para gravação lacrada.
//
// Objetivo forense: comprovar que a trilha de áudio compartilhada pelo
// operador realmente carregava sinal durante a coleta. Um vídeo "mudo"
// costuma vir de aba compartilhada SEM "Compartilhar áudio da aba",
// ou de aba com volume zerado.
//
// Não grava nada: apenas mede RMS/pico via AnalyserNode.

export interface AudioLevelState {
  /** RMS instantâneo normalizado (0..1). */
  level: number;
  /** Pico observado desde o início (0..1). */
  peak: number;
  /** true quando algum sinal audível foi observado. */
  hadSound: boolean;
  /** Tempo contínuo de silêncio em ms. */
  silentMs: number;
}

const SILENCE_THRESHOLD = 0.008;

export interface AudioCaptureInfo {
  tracks: number;
  labels: string[];
  mic_mixed: boolean;
  /** true quando nenhum sinal audível foi detectado em toda a coleta. */
  silent: boolean;
  /** true quando o arquivo final acabou sem trilha de áudio. */
  lost: boolean;
  peak_level: number;
  operator_accepted_no_audio: boolean;
}

export class AudioLevelMonitor {
  private ctx: AudioContext | null = null;
  private analyser: AnalyserNode | null = null;
  private source: MediaStreamAudioSourceNode | null = null;
  private timer: number | null = null;
  private buf: Float32Array<ArrayBuffer> | null = null;
  private lastSoundAt = Date.now();
  private state: AudioLevelState = { level: 0, peak: 0, hadSound: false, silentMs: 0 };

  start(stream: MediaStream, onUpdate?: (s: AudioLevelState) => void) {
    try {
      if (stream.getAudioTracks().length === 0) return;
      const Ctor: typeof AudioContext =
        (window as unknown as { AudioContext: typeof AudioContext }).AudioContext ||
        (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      const ctx = new Ctor();
      const analyser = ctx.createAnalyser();
      analyser.fftSize = 2048;
      const source = ctx.createMediaStreamSource(stream);
      source.connect(analyser);
      this.ctx = ctx;
      this.analyser = analyser;
      this.source = source;
      this.buf = new Float32Array(new ArrayBuffer(analyser.fftSize * 4));
      this.lastSoundAt = Date.now();
      void ctx.resume().catch(() => undefined);

      this.timer = window.setInterval(() => {
        if (!this.analyser || !this.buf) return;
        this.analyser.getFloatTimeDomainData(this.buf);
        let sum = 0;
        for (let i = 0; i < this.buf.length; i++) sum += this.buf[i] * this.buf[i];
        const rms = Math.sqrt(sum / this.buf.length);
        if (rms > SILENCE_THRESHOLD) {
          this.lastSoundAt = Date.now();
          this.state.hadSound = true;
        }
        this.state.level = rms;
        this.state.peak = Math.max(this.state.peak, rms);
        this.state.silentMs = Date.now() - this.lastSoundAt;
        onUpdate?.({ ...this.state });
      }, 250);
    } catch {
      /* monitor é auxiliar — nunca deve quebrar a gravação */
    }
  }

  getState(): AudioLevelState {
    return { ...this.state };
  }

  stop() {
    if (this.timer != null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
    try {
      this.source?.disconnect();
    } catch {
      /* noop */
    }
    try {
      void this.ctx?.close();
    } catch {
      /* noop */
    }
    this.source = null;
    this.analyser = null;
    this.ctx = null;
  }
}

export interface MixedAudioResult {
  /** Trilha resultante da mistura (aba + microfone). */
  track: MediaStreamTrack;
  /** Contexto e fontes para encerramento posterior. */
  dispose: () => void;
}

/**
 * Mistura o áudio da aba compartilhada com o microfone do operador em uma
 * única trilha, permitindo narração do procedimento durante a coleta.
 */
export async function mixDisplayAndMicAudio(
  displayStream: MediaStream,
  micStream: MediaStream,
): Promise<MixedAudioResult | null> {
  try {
    const Ctor: typeof AudioContext =
      (window as unknown as { AudioContext: typeof AudioContext }).AudioContext ||
      (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
    const ctx = new Ctor();
    const dest = ctx.createMediaStreamDestination();
    const nodes: MediaStreamAudioSourceNode[] = [];

    if (displayStream.getAudioTracks().length > 0) {
      const n = ctx.createMediaStreamSource(new MediaStream(displayStream.getAudioTracks()));
      n.connect(dest);
      nodes.push(n);
    }
    if (micStream.getAudioTracks().length > 0) {
      const gain = ctx.createGain();
      gain.gain.value = 0.9;
      const n = ctx.createMediaStreamSource(new MediaStream(micStream.getAudioTracks()));
      n.connect(gain);
      gain.connect(dest);
      nodes.push(n);
    }

    const track = dest.stream.getAudioTracks()[0];
    if (!track) {
      void ctx.close().catch(() => undefined);
      return null;
    }
    await ctx.resume().catch(() => undefined);
    return {
      track,
      dispose: () => {
        nodes.forEach((n) => {
          try {
            n.disconnect();
          } catch {
            /* noop */
          }
        });
        try {
          void ctx.close();
        } catch {
          /* noop */
        }
      },
    };
  } catch {
    return null;
  }
}

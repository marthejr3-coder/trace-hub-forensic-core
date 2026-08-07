import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Loader2,
  Globe,
  Hash,
  Camera,
  Square,
  ShieldCheck,
  AlertTriangle,
  Video,
  VideoOff,
  Download,
  Anchor,
  CheckCircle2,
  Mic,
  Volume2,
  VolumeX,
} from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  AudioLevelMonitor,
  mixDisplayAndMicAudio,
  type AudioCaptureInfo,
  type AudioLevelState,
} from "@/lib/forensic-integrity/audio-level-monitor";
import { useSealedSession, type SealedFinalizeResult } from "@/hooks/useSealedSession";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import type { SealedVideoMeta } from "@/components/sealed-capture/SealedCaptureLauncher";
import { downloadSealedVideo, buildFriendlyFilename, formatMB } from "@/lib/sealed-video-download";
import { useForensicIntegrity } from "@/hooks/useForensicIntegrity";
import {
  CaptureSurfaceWatcher,
  FrameHashChain,
  PIXEL_ONLY_WARNING,
  classifyObservationScope,
  type FrameChainLink,
  type ObservationScopeInfo,
  type SurfaceEvent,
} from "@/lib/forensic-integrity/capture-observation";
import {
  buildIntegrityAuditReport,
  buildSealedForensicPackage,
  sealManifest,
  type ArtifactEntry,
  type ArtifactManifest,
  type IntegrityAuditReport,
  type SealedEventRecord,
} from "@/lib/forensic-integrity";
import { DisplayAudioCompatibilityError, requestDisplayMediaWithAudio } from "@/lib/display-media-audio";
import {
  cleanupAbandonedSealedRecordings,
  SealedRecordingStore,
  type SealedRecordingResult,
} from "@/lib/sealed-recording-store";
import { uploadSealedVideoResumable } from "@/lib/resumable-storage-upload";



const CHANNEL_NAME = "trace-hub-sealed-capture";

function probeVideoDuration(blob: Blob): Promise<number | null> {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(blob);
    const v = document.createElement("video");
    v.preload = "metadata";
    v.muted = true;
    const done = (val: number | null) => {
      try {
        URL.revokeObjectURL(url);
      } catch {
        /* noop */
      }
      resolve(val);
    };
    const guard = setTimeout(() => done(null), 3000);
    v.onloadedmetadata = () => {
      clearTimeout(guard);
      const d = v.duration;
      done(Number.isFinite(d) && d > 0 ? d : null);
    };
    v.onerror = () => {
      clearTimeout(guard);
      done(null);
    };
    v.src = url;
  });
}

function pickMimeType(): { mime: string; ext: string } {
  const candidates: Array<{ mime: string; ext: string }> = [
    { mime: "video/webm;codecs=vp9,opus", ext: "webm" },
    { mime: "video/webm;codecs=vp8,opus", ext: "webm" },
    { mime: "video/webm", ext: "webm" },
    { mime: "video/mp4;codecs=avc1,mp4a.40.2", ext: "mp4" },
    { mime: "video/mp4", ext: "mp4" },
  ];
  for (const c of candidates) {
    if (typeof MediaRecorder !== "undefined" && MediaRecorder.isTypeSupported(c.mime)) return c;
  }
  return { mime: "video/webm", ext: "webm" };
}

function extFromMime(mime?: string): string {
  const normalized = mime?.toLowerCase() ?? "";
  if (normalized.includes("mp4")) return "mp4";
  if (normalized.includes("quicktime") || normalized.includes("mov")) return "mov";
  if (normalized.includes("matroska") || normalized.includes("mkv")) return "mkv";
  return "webm";
}

function createRecorder(stream: MediaStream, preferred: { mime: string; ext: string }) {
  try {
    const recorder = preferred.mime
      ? new MediaRecorder(stream, { mimeType: preferred.mime })
      : new MediaRecorder(stream);
    const actualMime = recorder.mimeType || preferred.mime || "video/webm";
    return { recorder, mime: { mime: actualMime, ext: extFromMime(actualMime) } };
  } catch {
    const recorder = new MediaRecorder(stream);
    const actualMime = recorder.mimeType || preferred.mime || "video/webm";
    return { recorder, mime: { mime: actualMime, ext: extFromMime(actualMime) } };
  }
}

function formatTimer(ms: number) {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60)
    .toString()
    .padStart(2, "0");
  const s = (total % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

type CaptureStats = {
  startedAt: number;
  stopRequestedAt: number;
  lastChunkAt: number;
  chunkCount: number;
  totalBytes: number;
};

/**
 * Ambiente Lacrado em aba dedicada.
 * Recebe a URL alvo via query (?u=...&record=1&channel=...).
 * Cria a sessão, carrega o iframe proxied, dispara getDisplayMedia,
 * orienta o operador a selecionar a aba real do alvo, grava, finaliza e devolve o resultado ao opener via
 * BroadcastChannel + window.postMessage.
 */
export default function SealedCapture() {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("u") || "";
  const recordPref = params.get("record") !== "0";
  const channelId = params.get("channel") || CHANNEL_NAME;
  const socialMode = params.get("social") === "1";
  const strictMode = params.get("strict") === "1";

  const [iframeSrc, setIframeSrc] = useState<string | null>(null);
  const [iframeLoaded, setIframeLoaded] = useState(false);
  const [recording, setRecording] = useState(false);
  const [pickerArmed, setPickerArmed] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [uploadingVideo, setUploadingVideo] = useState(false);
  const [finalizing, setFinalizing] = useState(false);
  const [done, setDone] = useState<(SealedFinalizeResult & SealedVideoMeta) | null>(null);
  const [uploadFailed, setUploadFailed] = useState(false);
  const [retryingUpload, setRetryingUpload] = useState(false);
  const [captureIssue, setCaptureIssue] = useState<string | null>(null);
  const [finalizationPhase, setFinalizationPhase] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const recordedBlobRef = useRef<File | null>(null);

  const startedAtRef = useRef(0);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const recordingStoreRef = useRef<SealedRecordingStore | null>(null);
  const recordingResultRef = useRef<SealedRecordingResult | null>(null);
  const mimeRef = useRef<{ mime: string; ext: string }>({ mime: "video/webm", ext: "webm" });
  const channelRef = useRef<BroadcastChannel | null>(null);
  const initRef = useRef(false);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const stopPromiseRef = useRef<Promise<File | null> | null>(null);
  const backpressureRef = useRef<Promise<void> | null>(null);
  const captureStatsRef = useRef<CaptureStats>({
    startedAt: 0,
    stopRequestedAt: 0,
    lastChunkAt: 0,
    chunkCount: 0,
    totalBytes: 0,
  });
  const [closingVideo, setClosingVideo] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [mediaReady, setMediaReady] = useState(false);
  const mediaReadyRef = useRef(false);
  const [streamConnected, setStreamConnected] = useState(false);
  const streamConnectedRef = useRef(false);
  const probeVideoRef = useRef<HTMLVideoElement | null>(null);
  const frameDetectedRef = useRef(false);

  // ── Áudio da gravação ─────────────────────────────────────────────────────
  const audioMonitorRef = useRef<AudioLevelMonitor | null>(null);
  const micStreamRef = useRef<MediaStream | null>(null);
  const micDisposeRef = useRef<(() => void) | null>(null);
  const audioInfoRef = useRef<AudioCaptureInfo>({
    tracks: 0,
    labels: [],
    mic_mixed: false,
    silent: true,
    lost: false,
    peak_level: 0,
    operator_accepted_no_audio: false,
  });
  const [includeMic, setIncludeMic] = useState(false);
  const [audioLevel, setAudioLevel] = useState<AudioLevelState | null>(null);
  const [audioSilentAlert, setAudioSilentAlert] = useState(false);
  const audioSilentToastRef = useRef(false);
  const [noAudioPrompt, setNoAudioPrompt] = useState(false);

  // ── Observação da superfície gravada + cadeia de frames ───────────────────
  const surfaceWatcherRef = useRef<CaptureSurfaceWatcher | null>(null);
  const frameChainRef = useRef<FrameHashChain | null>(null);
  const [observation, setObservation] = useState<ObservationScopeInfo | null>(null);
  const [surfaceEvents, setSurfaceEvents] = useState<SurfaceEvent[]>([]);
  const [frameLinks, setFrameLinks] = useState<FrameChainLink[]>([]);

  const { session, start, logEvent, finalize, proxyUrlFor, eventCount } = useSealedSession();

  // ── Integridade Forense Avançada ──────────────────────────────────────────
  const getObservedDocument = useRef(() => {
    try {
      // Só observamos o iframe (proxy same-origin). Se estiver inacessível
      // (cross-origin ou ainda não carregado), devolvemos null — NUNCA o
      // document do próprio app, pois cada log gera setState → mutação DOM
      // → novo snapshot → loop de sealed-session-event.
      return iframeRef.current?.contentDocument ?? null;
    } catch {
      return null;
    }
  }).current;

  const integrity = useForensicIntegrity({
    active: !!session && !done,
    logEvent: logEvent as never,
    getDocument: getObservedDocument,
    mode: strictMode ? "abort" : "warn",
    onAbort: (ev) => {
      toast.error(
        `Modo estrito: coleta interrompida por sinal de adulteração do ambiente (${ev.method}).`,
        { duration: 12000 },
      );
      void stopRecording();
    },
  });
  const [packageState, setPackageState] = useState<{
    manifest: ArtifactManifest;
    audit: IntegrityAuditReport;
    events: SealedEventRecord[];
    files: Array<{ file_name: string; blob: Blob }>;
  } | null>(null);
  const [buildingZip, setBuildingZip] = useState(false);

  function openTargetTab() {
    try {
      let normalized = targetUrl.trim();
      if (!/^https?:\/\//i.test(normalized)) normalized = "https://" + normalized;
      window.open(normalized, "_blank", "noopener");
    } catch {
      /* noop */
    }
  }

  // Inicializa o canal de comunicação com a aba opener.
  useEffect(() => {
    try {
      channelRef.current = new BroadcastChannel(channelId);
    } catch {
      channelRef.current = null;
    }
    return () => {
      try {
        channelRef.current?.close();
      } catch {
        /* noop */
      }
    };
  }, [channelId]);

  useEffect(() => {
    void cleanupAbandonedSealedRecordings();
    return () => {
      void recordingStoreRef.current?.discard().catch(() => undefined);
    };
  }, []);

  // Timer do tempo de sessão.
  useEffect(() => {
    if (!session) return;
    startedAtRef.current = Date.now();
    const id = setInterval(() => setElapsed(Date.now() - startedAtRef.current), 1000);
    return () => clearInterval(id);
  }, [session]);

  // Cria sessão + carrega iframe automaticamente assim que a aba abrir.
  useEffect(() => {
    if (initRef.current) return;
    if (!targetUrl) {
      setError("URL alvo ausente.");
      return;
    }
    initRef.current = true;
    (async () => {
      try {
        let normalized = targetUrl.trim();
        if (!/^https?:\/\//i.test(normalized)) normalized = "https://" + normalized;
        try {
          new URL(normalized);
        } catch {
          throw new Error("URL inválida");
        }
        const s = await start(normalized);
        if (socialMode) {
          // Para redes sociais o proxy lacrado mostra só tela de login (sem cookies do operador).
          // Pulamos o iframe; o operador vai compartilhar a aba REAL já logada.
          setIframeSrc(null);
          setIframeLoaded(true);
        } else {
          const proxied = await proxyUrlFor(normalized, s);
          setIframeSrc(proxied);
        }
        try {
          await logEvent("navigation", { url: normalized, kind: "start", social_mode: socialMode }, s);
        } catch {
          /* noop */
        }
        document.title = `Ambiente Lacrado — ${new URL(normalized).hostname}`;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        toast.error(msg);
      }
    })();
  }, [targetUrl, start, proxyUrlFor, logEvent, socialMode]);

  function resetCaptureStats() {
    captureStatsRef.current = {
      startedAt: Date.now(),
      stopRequestedAt: 0,
      lastChunkAt: 0,
      chunkCount: 0,
      totalBytes: 0,
    };
  }

  function markMediaReady() {
    if (!mediaReadyRef.current) {
      mediaReadyRef.current = true;
      setMediaReady(true);
    }
  }

  function registerChunk(chunk: Blob) {
    if (!chunk || chunk.size <= 0) return;
    const store = recordingStoreRef.current;
    if (!store) return;
    const write = store.append(chunk);
    captureStatsRef.current.chunkCount += 1;
    captureStatsRef.current.totalBytes += chunk.size;
    captureStatsRef.current.lastChunkAt = Date.now();
    markMediaReady();

    // MediaRecorder pode produzir dados mais rápido que o disco. Sem
    // backpressure, cada Promise pendente retém seu Blob e recria uma fila
    // ilimitada em RAM. Pausamos cedo e retomamos somente depois da drenagem.
    const MAX_PENDING_BYTES = 12 * 1024 * 1024;
    const recorder = recorderRef.current;
    if (store.pendingBytes >= MAX_PENDING_BYTES && recorder?.state === "recording" && !backpressureRef.current) {
      try {
        recorder.pause();
      } catch {
        /* noop */
      }
      const drain = store.drain()
        .then(() => {
          if (recorderRef.current === recorder && recorder.state === "paused") recorder.resume();
        })
        .catch((reason) => {
          setCaptureIssue(reason instanceof Error ? reason.message : String(reason));
          if (recorder.state !== "inactive") recorder.stop();
        })
        .finally(() => {
          if (backpressureRef.current === drain) backpressureRef.current = null;
        });
      backpressureRef.current = drain;
    }
    void write.catch((reason) => {
      setCaptureIssue(reason instanceof Error ? reason.message : String(reason));
    });
  }

  /**
   * Detecta o primeiro frame REAL via <video> oculto.
   * Independe do MediaRecorder — alguns browsers demoram pra disparar
   * ondataavailable mesmo com track produzindo frames. Aqui usamos
   * requestVideoFrameCallback (preferido) ou onplaying/ontimeupdate.
   */
  function attachFrameProbe(stream: MediaStream) {
    try {
      const v = document.createElement("video");
      v.muted = true;
      v.playsInline = true;
      v.autoplay = true;
      v.srcObject = stream;
      v.style.position = "fixed";
      v.style.left = "-9999px";
      v.style.width = "2px";
      v.style.height = "2px";
      v.style.opacity = "0";
      document.body.appendChild(v);
      probeVideoRef.current = v;
      const onFrame = () => {
        if (frameDetectedRef.current) return;
        frameDetectedRef.current = true;
        markMediaReady();
        // força flush logo após primeiro frame detectado
        try {
          recorderRef.current?.requestData();
        } catch {
          /* noop */
        }
      };
      // Preferência: rVFC (Chromium/Safari recentes)
      const anyV = v as unknown as {
        requestVideoFrameCallback?: (cb: () => void) => number;
      };
      if (typeof anyV.requestVideoFrameCallback === "function") {
        anyV.requestVideoFrameCallback(onFrame);
      }
      // Fallbacks universais
      v.onplaying = onFrame;
      v.ontimeupdate = () => {
        if (v.currentTime > 0) onFrame();
      };
      v.play().catch(() => {
        /* gesto já válido via getDisplayMedia */
      });
    } catch (err) {
      console.warn("frame probe failed", err);
    }
  }

  function detachFrameProbe() {
    const v = probeVideoRef.current;
    if (!v) return;
    try {
      v.pause();
    } catch {
      /* noop */
    }
    try {
      v.srcObject = null;
    } catch {
      /* noop */
    }
    try {
      v.remove();
    } catch {
      /* noop */
    }
    probeVideoRef.current = null;
  }

  function describeEmptyCapture() {
    const stats = captureStatsRef.current;
    const elapsedMs = Math.max(0, (stats.stopRequestedAt || Date.now()) - (stats.startedAt || Date.now()));
    if (!stats.chunkCount) {
      if (frameDetectedRef.current) {
        return "O navegador detectou frames da aba, mas não entregou nenhum byte ao gravador. Isso costuma acontecer quando a aba alvo ficou em segundo plano. Mantenha a aba visível e tente novamente.";
      }
      if (elapsedMs < 1500) {
        return "A gravação foi encerrada cedo demais e o navegador não chegou a produzir frames. Tente novamente e aguarde alguns segundos antes de parar.";
      }
      return "A aba não chegou a renderizar frames durante a gravação. Confirme que a aba escolhida está visível e tente novamente.";
    }
    return "O navegador chegou a iniciar a captura, mas não consolidou um arquivo de vídeo utilizável.";
  }

  function stopAudioMonitoring() {
    try {
      audioMonitorRef.current?.stop();
    } catch {
      /* noop */
    }
    audioMonitorRef.current = null;
    try {
      micDisposeRef.current?.();
    } catch {
      /* noop */
    }
    micDisposeRef.current = null;
    try {
      micStreamRef.current?.getTracks().forEach((t) => t.stop());
    } catch {
      /* noop */
    }
    micStreamRef.current = null;
  }

  async function startRecording(opts?: { allowNoAudio?: boolean }) {
    if (!navigator.mediaDevices?.getDisplayMedia) {
      toast.error("Este navegador não suporta gravação de tela.");
      return false;
    }
    setPickerArmed(true);
    setNoAudioPrompt(false);
    try {
      const stream = await requestDisplayMediaWithAudio(navigator.mediaDevices);

      // ── Gate de áudio: sem trilha de áudio a gravação NÃO começa ───────────
      if (stream.getAudioTracks().length === 0 && !opts?.allowNoAudio) {
        try {
          stream.getTracks().forEach((t) => t.stop());
        } catch {
          /* noop */
        }
        try {
          await logEvent("user_action", { kind: "audio_missing_blocked" });
        } catch {
          /* noop */
        }
        setNoAudioPrompt(true);
        return false;
      }

      streamRef.current = stream;

      // ── Microfone opcional (narração do operador) ─────────────────────────
      stopAudioMonitoring();
      let micMixed = false;
      if (includeMic) {
        try {
          const mic = await navigator.mediaDevices.getUserMedia({
            audio: { echoCancellation: true, noiseSuppression: true },
          });
          micStreamRef.current = mic;
          const mixed = await mixDisplayAndMicAudio(stream, mic);
          if (mixed) {
            stream.getAudioTracks().forEach((t) => {
              try {
                stream.removeTrack(t);
                t.stop();
              } catch {
                /* noop */
              }
            });
            stream.addTrack(mixed.track);
            micDisposeRef.current = mixed.dispose;
            micMixed = true;
          }
        } catch (micErr) {
          console.warn("mic capture failed", micErr);
          toast.warning("Microfone indisponível — a gravação segue com o áudio da aba.");
        }
      }

      const audioTracks = stream.getAudioTracks();
      audioInfoRef.current = {
        tracks: audioTracks.length,
        labels: audioTracks.map((t) => t.label),
        mic_mixed: micMixed,
        silent: true,
        lost: false,
        peak_level: 0,
        operator_accepted_no_audio: audioTracks.length === 0,
      };
      audioSilentToastRef.current = false;
      setAudioSilentAlert(false);
      setAudioLevel(null);

      if (audioTracks.length === 0) {
        toast.warning(
          "Gravando SEM áudio por decisão do operador — isso ficará registrado no relatório.",
          { duration: 9000 },
        );
      } else {
        const monitor = new AudioLevelMonitor();
        audioMonitorRef.current = monitor;
        monitor.start(stream, (s) => {
          setAudioLevel(s);
          audioInfoRef.current.peak_level = Math.max(audioInfoRef.current.peak_level, s.peak);
          if (s.hadSound) {
            audioInfoRef.current.silent = false;
            setAudioSilentAlert(false);
          } else if (s.silentMs > 10_000 && !audioSilentToastRef.current) {
            audioSilentToastRef.current = true;
            setAudioSilentAlert(true);
            toast.warning(
              "A trilha de áudio está em silêncio absoluto há mais de 10s. Confirme se a opção Compartilhar áudio da aba foi marcada e se o vídeo está tocando.",
              { duration: 12000 },
            );
            void logEvent("user_action", { kind: "audio_silence_detected", silent_ms: Math.round(s.silentMs) }).catch(
              () => undefined,
            );
          }
        });
        toast.success(micMixed ? "Áudio da aba + microfone ativos." : "Fonte de áudio detectada na captura.");
      }

      if (recordingStoreRef.current) {
        await recordingStoreRef.current.discard().catch(() => undefined);
      }
      recordingStoreRef.current = null;
      recordingResultRef.current = null;
      resetCaptureStats();
      recordedBlobRef.current = null;
      stopPromiseRef.current = null;
      mediaReadyRef.current = false;
      setMediaReady(false);
      frameDetectedRef.current = false;
      streamConnectedRef.current = true;
      setStreamConnected(true);
      setCaptureIssue(null);
      setUploadFailed(false);
      setClosingVideo(false);

      // Probe paralela: <video> oculto detecta primeiro frame real,
      // independente do MediaRecorder.
      attachFrameProbe(stream);
      startSurfaceObservation(stream);

      // Sinais da própria track — alguns browsers disparam "unmute" quando
      // a aba alvo começa a produzir frames.
      const vTrack = stream.getVideoTracks()[0];
      if (vTrack) {
        if (vTrack.muted === false && vTrack.readyState === "live") {
          // já viva — provavelmente vai produzir frame logo
        }
        vTrack.addEventListener("unmute", () => {
          // unmute = browser confirmou que frames vão começar a chegar
          markMediaReady();
          try {
            recorderRef.current?.requestData();
          } catch {
            /* noop */
          }
        });
        vTrack.addEventListener(
          "ended",
          () => {
            void logEvent("user_action", { kind: "sharing_stopped_by_user" }).catch(() => undefined);
            stopRecording()
              .then((blob) => {
                if (blob && blob.size > 0) {
                  toast.info('Gravação encerrada — clique em "Encerrar & lacrar" para enviar.');
                } else {
                  toast.warning(
                    'Compartilhamento encerrado sem arquivo de vídeo utilizável. Clique em "Encerrar & lacrar" para concluir a sessão.',
                    { duration: 10000 },
                  );
                }
              })
              .catch(() => {
                setClosingVideo(false);
                toast.warning(
                  'O navegador falhou ao fechar o vídeo. A sessão segue lacrável: clique em "Encerrar & lacrar".',
                  { duration: 10000 },
                );
              });
          },
          { once: true },
        );

      }

      const preferredMime = pickMimeType();
      const { recorder, mime } = createRecorder(stream, preferredMime);
      mimeRef.current = mime;
      const recordingId = session?.id ?? crypto.randomUUID();
      const store = new SealedRecordingStore(recordingId, mime.mime, mime.ext);
      await store.initialize();
      recordingStoreRef.current = store;
      recorder.ondataavailable = (event) => {
        registerChunk(event.data);
      };
      recorder.onerror = (ev) => {
        console.error("MediaRecorder error", ev);
      };
      recorderRef.current = recorder;
      // 500ms timeslice — chunks chegam mais rápido pra liberar "Parar gravação" antes
      recorder.start(500);
      // Pinga requestData cedo pra forçar o primeiro chunk em browsers preguiçosos
      window.setTimeout(() => {
        try {
          if (recorder.state === "recording") recorder.requestData();
        } catch {
          /* noop */
        }
      }, 800);
      window.setTimeout(() => {
        try {
          if (recorder.state === "recording") recorder.requestData();
        } catch {
          /* noop */
        }
      }, 2000);
      setRecording(true);
      try {
        await logEvent("user_action", {
          kind: "recording_started",
          mime: mimeRef.current.mime,
          audio_tracks: audioTracks.length,
          audio_track_labels: audioTracks.map((track) => track.label),
          mic_mixed: audioInfoRef.current.mic_mixed,
          operator_accepted_no_audio: audioInfoRef.current.operator_accepted_no_audio,
        });
      } catch {
        /* noop */
      }
      toast.success("Gravação iniciada");
      return true;
    } catch (e) {
      cleanupRecorder();
      await recordingStoreRef.current?.discard().catch(() => undefined);
      recordingStoreRef.current = null;
      recordingResultRef.current = null;
      const name = (e as { name?: string })?.name;
      const msg = e instanceof Error ? e.message : String(e);
      if (e instanceof DisplayAudioCompatibilityError) {
        toast.error(e.message, { duration: 12000 });
      } else if (/transient activation/i.test(msg)) {
        toast.error('O navegador exige um clique direto. Clique novamente em "Gravar tela".');
      } else if (name === "NotAllowedError" || name === "AbortError") {
        toast.info("Gravação cancelada. A sessão segue lacrada sem vídeo.");
      } else {
        toast.error(msg);
      }
      return false;
    } finally {
      setPickerArmed(false);
    }
  }

  /**
   * Classifica o escopo de observação e liga os sensores que funcionam mesmo
   * quando o alvo está numa aba EXTERNA (cross-origin), onde nenhum código web
   * consegue ler o DOM: vigilância de dimensões/troca da superfície e cadeia de
   * hash de frames amostrados.
   */
  function startSurfaceObservation(stream: MediaStream) {
    stopSurfaceObservation();
    const track = stream.getVideoTracks()[0];
    // A própria aba do Trace Hub é excluída do seletor (selfBrowserSurface:
    // "exclude"), logo a superfície gravada é sempre externa ao documento
    // observado pela cadeia de DOM: gravação pixel-only.
    const info = classifyObservationScope(track, false);
    setObservation(info);
    setSurfaceEvents([]);
    setFrameLinks([]);
    void logEvent("user_action", {
      kind: "observation_scope_declared",
      scope: info.scope,
      display_surface: info.display_surface,
      dom_observable: info.dom_observable,
      initial_frame_size: info.initial_frame_size,
      strict_mode: strictMode,
    });

    if (track) {
      const watcher = new CaptureSurfaceWatcher(track, {
        onEvent: (ev) => {
          setSurfaceEvents((prev) => [...prev, ev]);
          void logEvent("tamper", { kind: ev.kind, details: ev.details, ts_client: ev.timestamp });
          if (ev.kind === "captured_surface_resize" || ev.kind === "surface_switched") {
            integrity.reportTamper(ev.kind, ev.details);
            toast.warning(
              ev.kind === "surface_switched"
                ? "A superfície compartilhada mudou durante a coleta. O evento foi registrado na cadeia."
                : "A superfície gravada mudou de tamanho (indício de inspetor/DevTools aberto na aba alvo). Evento registrado na cadeia.",
              { duration: 10000 },
            );
            if (strictMode) {
              toast.error("Modo estrito: coleta interrompida por anomalia da superfície gravada.", {
                duration: 12000,
              });
              void stopRecording();
            }
          }
        },
      });
      surfaceWatcherRef.current = watcher;
      watcher.start();
    }

    const probe = probeVideoRef.current;
    if (probe) {
      const chain = new FrameHashChain(probe, {
        intervalMs: 1000,
        onLink: (l) => setFrameLinks((prev) => (prev.length >= 5000 ? prev : [...prev, l])),
      });
      frameChainRef.current = chain;
      chain.start();
    }
  }

  function stopSurfaceObservation() {
    try {
      surfaceWatcherRef.current?.stop();
    } catch {
      /* noop */
    }
    try {
      frameChainRef.current?.stop();
    } catch {
      /* noop */
    }
    surfaceWatcherRef.current = null;
    frameChainRef.current = null;
  }

  async function finalizeRecordingFile(): Promise<File | null> {
    if (recordingResultRef.current) return recordingResultRef.current.file;
    const result = await recordingStoreRef.current?.finalize();
    if (!result?.file.size) return null;
    recordingResultRef.current = result;
    return result.file;
  }


  function stopTracksOnly() {
    try {
      streamRef.current?.getTracks().forEach((t) => {
        try {
          t.stop();
        } catch {
          /* noop */
        }
      });
    } catch {
      /* noop */
    }
    streamRef.current = null;
  }

  function cleanupRecorder() {
    stopSurfaceObservation();
    detachFrameProbe();
    stopTracksOnly();
    const audioState = audioMonitorRef.current?.getState();
    if (audioState) {
      audioInfoRef.current.peak_level = Math.max(audioInfoRef.current.peak_level, audioState.peak);
      if (audioState.hadSound) audioInfoRef.current.silent = false;
    }
    stopAudioMonitoring();
    setAudioLevel(null);
    recorderRef.current = null;
    setRecording(false);
    streamConnectedRef.current = false;
    setStreamConnected(false);
  }

  /**
   * Fechamento determinístico do MediaRecorder.
   *
   * Spec: o navegador GARANTE que todos os eventos `dataavailable`
   * disparam ANTES do `onstop`. Então o caminho correto é:
   *   1. requestData() para flush imediato do buffer atual
   *   2. stop()
   *   3. esperar onstop
   *   4. só então montar o Blob e parar as tracks
   *
   * Tudo isso fica dentro de uma única promessa deduplicada por
   * stopPromiseRef, então `Parar gravação`, fim do compartilhamento e
   * `Encerrar & lacrar` reutilizam o mesmo fechamento.
   */
  async function stopRecording(): Promise<File | null> {
    if (stopPromiseRef.current) return stopPromiseRef.current;

    // Caso 1: blob já consolidado anteriormente
    if (recordedBlobRef.current) return recordedBlobRef.current;

    const rec = recorderRef.current;
    if (!rec) {
      // Sem recorder ativo — conclui o arquivo temporário que houver.
      const blob = await finalizeRecordingFile();
      if (blob) recordedBlobRef.current = blob;
      else setCaptureIssue(describeEmptyCapture());
      return recordedBlobRef.current;
    }

    captureStatsRef.current.stopRequestedAt = Date.now();
    setClosingVideo(true);

    const promise = (async (): Promise<File | null> => {
      // Se o gravador foi pausado para o disco alcançar o produtor, aguarda a
      // fila curta terminar antes do flush final. Isso evita deixar um
      // MediaRecorder pausado vivo enquanto o arquivo já está sendo lacrado.
      if (backpressureRef.current) {
        await backpressureRef.current.catch(() => undefined);
      }
      if (rec.state === "paused") {
        try {
          rec.resume();
        } catch {
          /* noop */
        }
      }

      // FASE 1 — aquecimento: se nenhum chunk chegou ainda, espera ativamente
      // até 6s, pingando requestData() a cada 400ms. Se já houver frame
      // detectado pela probe, estende em mais 2s pra dar tempo do MediaRecorder
      // efetivamente entregar bytes (alguns browsers atrasam o 1º chunk
      // mesmo com a track já produzindo frames).
      if (captureStatsRef.current.chunkCount === 0 && rec.state === "recording") {
        const baseDeadline = Date.now() + 6000;
        const extendedDeadline = Date.now() + 8000;
        while (
          captureStatsRef.current.chunkCount === 0 &&
          rec.state === "recording" &&
          Date.now() < (frameDetectedRef.current ? extendedDeadline : baseDeadline)
        ) {
          try {
            rec.requestData();
          } catch {
            /* noop */
          }
          await new Promise((r) => window.setTimeout(r, 400));
        }
      }

      // FASE 2 — stop determinístico (requestData -> stop -> onstop)
      // Após onstop, ainda damos uma janela curta para chunks tardios chegarem
      // antes de declarar falha. Se houver frames detectados mas nenhum chunk,
      // estendemos essa janela final.
      return await new Promise<File | null>((resolve) => {
        let settled = false;

        const tryFinalize = async () => {
          if (settled) return;
          // Janela de tolerância pós-stop: chunks podem chegar nos próximos ms.
          // Se já temos chunks, finaliza em 120ms. Senão, espera até 2.5s
          // (4s se houve frame detectado) pingando requestData uma última vez.
          const postDeadline =
            Date.now() + (captureStatsRef.current.chunkCount > 0 ? 120 : frameDetectedRef.current ? 4000 : 2500);
          while (!settled && captureStatsRef.current.chunkCount === 0 && Date.now() < postDeadline) {
            try {
              rec.requestData();
            } catch {
              /* noop */
            }
            await new Promise((r) => window.setTimeout(r, 250));
          }
          if (settled) return;
          settled = true;
          const blob = await finalizeRecordingFile();
          if (blob) {
            recordedBlobRef.current = blob;
            setCaptureIssue(null);
          } else {
            setCaptureIssue(describeEmptyCapture());
          }
          cleanupRecorder();
          setClosingVideo(false);
          resolve(recordedBlobRef.current);
        };

        if (rec.state === "inactive") {
          void tryFinalize();
          return;
        }

        rec.onstop = () => {
          void tryFinalize();
        };
        rec.onerror = () => {
          void tryFinalize();
        };

        // Watchdog: se onstop nunca disparar em 12s, força.
        window.setTimeout(() => {
          if (!settled) void tryFinalize();
        }, 12_000);

        try {
          // Múltiplos requestData() antes do stop pra forçar o flush final
          // em browsers que só entregam bytes quando perguntados.
          if (rec.state === "recording") {
            try {
              rec.requestData();
            } catch {
              /* noop */
            }
            window.setTimeout(() => {
              try {
                if (rec.state === "recording") rec.requestData();
              } catch {
                /* noop */
              }
            }, 80);
            window.setTimeout(() => {
              try {
                if (rec.state === "recording") rec.requestData();
              } catch {
                /* noop */
              }
            }, 180);
          }
          window.setTimeout(() => {
            try {
              if (rec.state === "recording") rec.stop();
            } catch {
              /* noop */
            }
          }, 260);
        } catch {
          window.setTimeout(() => {
            void tryFinalize();
          }, 60);
        }
      });
    })()
      // Nunca rejeitar: uma falha aqui travaria `closingVideo` em true e
      // desabilitaria para sempre os botões de encerrar a sessão.
      .catch((e) => {
        console.error("sealed-capture: falha ao fechar a gravação", e);
        try {
          cleanupRecorder();
        } catch {
          /* noop */
        }
        if (!recordedBlobRef.current) setCaptureIssue(describeEmptyCapture());
        void logEvent("user_action", {
          kind: "recording_close_failed",
          reason: e instanceof Error ? e.message : String(e),
        }).catch(() => undefined);
        return recordedBlobRef.current;
      })
      // Garantia final: em qualquer desfecho os botões voltam a responder.
      .finally(() => {
        setClosingVideo(false);
      });

    stopPromiseRef.current = promise;
    promise.finally(() => {
      stopPromiseRef.current = null;
    });
    return promise;
  }



  async function uploadVideo(sessionId: string, userId: string, file: File) {
    setUploadingVideo(true);
    setUploadProgress(0);
    try {
      const ext = mimeRef.current.ext;
      const path = `${userId}/${sessionId}/sealed-${Date.now()}.${ext}`;
      return await uploadSealedVideoResumable({
        file,
        path,
        contentType: mimeRef.current.mime,
        onProgress: (uploaded, total) => {
          setUploadProgress(total > 0 ? Math.round((uploaded / total) * 100) : 0);
        },
      });
    } catch (e) {
      console.error("upload video failed", e);
      toast.error("Falha ao enviar vídeo — sessão segue lacrada sem mídia");
      return null;
    } finally {
      setUploadingVideo(false);
    }
  }

  async function handleScreenshot() {
    try {
      await logEvent("screenshot", {
        kind: "iframe_marker",
        viewport: { width: iframeRef.current?.clientWidth, height: iframeRef.current?.clientHeight },
        ts_client: new Date().toISOString(),
      });
      toast.success("Marca de captura registrada");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleFinalize() {
    if (finalizing) return;
    setFinalizing(true);
    setFinalizationPhase("Preparando vídeo…");
    try {
      const { data: u } = await supabase.auth.getUser();
      const userId = u?.user?.id ?? null;
      const sessionId = session?.id ?? null;
      try {
        await logEvent("user_action", { kind: "finalize_request" });
      } catch {
        /* noop */
      }

      let videoPath: string | null = null;
      let videoSignedUrl: string | null = null;
      let videoSha256: string | null = null;
      let videoSize: number | null = null;
      let videoMime: string | null = null;
      let videoDuration: number | null = null;
      let videoExpires: string | null = null;

      // Sempre aguardar o pipeline de gravação fechar antes de seguir,
      // mesmo que o usuário já tenha parado: o stopRecording é deduplicado
      // pelo stopPromiseRef, então é seguro chamar várias vezes.
      let blob: File | null = recordedBlobRef.current;
      if (recording || recorderRef.current || stopPromiseRef.current) {
        try {
          blob = await stopRecording();
        } catch {
          cleanupRecorder();
        }
      }
      // Reaproveita o blob final preservado em recordedBlobRef
      blob = blob ?? recordedBlobRef.current;

      if (blob && blob.size > 0) {
        recordedBlobRef.current = blob;

        if (!sessionId) {
          toast.error("Sessão lacrada ainda não está pronta. Tente encerrar novamente.");
          return;
        }

        if (!userId) {
          setUploadFailed(true);
          toast.error("Usuário não autenticado. O vídeo foi gravado, mas não pode ser enviado ainda.");
          return;
        }

        videoSize = blob.size;
        videoMime = mimeRef.current.mime;
        try {
          setFinalizationPhase("Calculando integridade…");
          videoSha256 = recordingResultRef.current?.sha256 ?? null;
          if (!videoSha256) throw new Error("Hash incremental da gravação indisponível");
        } catch {
          /* noop */
        }
        const stoppedAt = captureStatsRef.current.stopRequestedAt || Date.now();
        videoDuration = Math.max(0, (stoppedAt - captureStatsRef.current.startedAt) / 1000);
        if (videoSha256) {
          try {
            await logEvent("user_action", {
              kind: "video_hashed",
              sha256: videoSha256,
              size: videoSize,
              mime: videoMime,
              duration_seconds: videoDuration,
            });
          } catch {
            /* noop */
          }
        }
        setFinalizationPhase("Enviando vídeo…");
        const up = await uploadVideo(sessionId, userId, blob);
        if (up) {
          videoPath = up.path;
          videoSignedUrl = up.signedUrl;
          videoExpires = up.expiresAt;
          try {
            await logEvent("user_action", {
              kind: "video_uploaded",
              path: up.path,
              mime: videoMime,
              size: videoSize,
              sha256: videoSha256,
            });
          } catch {
            /* noop */
          }
        } else {
          setUploadFailed(true);
        }
      } else if (!blob) {
        console.warn("sealed-capture: nenhum blob consolidado", captureStatsRef.current);
      }

      // Fecha o registro de mutações do DOM antes de lacrar a cadeia.
      try {
        await integrity.flushMutations();
      } catch {
        /* noop */
      }

      const target = session?.target_url ?? targetUrl;
      setFinalizationPhase("Lacrando sessão…");
      const r = await finalize(videoPath ? { video_path: videoPath } : undefined);
      const enriched: SealedFinalizeResult & SealedVideoMeta = {
        ...r,
        video_path: videoPath,
        video_signed_url: videoSignedUrl,
        video_sha256: videoSha256,
        video_size: videoSize,
        video_mime: videoMime,
        video_duration_seconds: videoDuration,
        video_bucket: videoPath ? "sealed-capture" : null,
        video_signed_url_expires_at: videoExpires,
        target_url: target,
      };
      setDone(enriched);

      // Requisitos 6–9: manifesto de artefatos, Master Hash, auditoria e ancoragem.
      try {
        await sealForensicIntegrity(enriched, userId, {
          blob,
          sha256: videoSha256,
          mime: videoMime,
          path: videoPath,
          size: videoSize,
        });
      } catch (e) {
        console.error("sealed-capture: selagem forense falhou", e);
        toast.error("A sessão foi lacrada, mas o pacote de integridade não pôde ser selado.");
      }

      // Após upload e manifesto, a URL privada e o SHA-256 são a fonte da
      // verdade. Liberar o Blob evita manter a gravação inteira na RAM.
      if (videoPath) {
        recordedBlobRef.current = null;
        recordingResultRef.current = null;
        await recordingStoreRef.current?.discard().catch(() => undefined);
        recordingStoreRef.current = null;
      }

      // Notifica a aba opener (se ainda estiver escutando).
      try {
        channelRef.current?.postMessage({ type: "sealed-capture:finalized", payload: enriched });
      } catch {
        /* noop */
      }
      try {
        window.opener?.postMessage({ type: "sealed-capture:finalized", payload: enriched }, window.location.origin);
      } catch {
        /* noop */
      }
      toast.success("Sessão lacrada e ancorada");
      // NÃO fechamos a aba automaticamente — o usuário precisa baixar o vídeo aqui.
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setFinalizing(false);
      setFinalizationPhase(null);
    }
  }

  /**
   * Requisitos 6–9 e 11: monta o manifesto de artefatos, calcula o Master Hash,
   * gera o Relatório de Auditoria de Integridade, persiste os artefatos JSON no
   * depósito privado e ancora o Master Hash.
   */
  async function sealForensicIntegrity(
    result: SealedFinalizeResult & SealedVideoMeta,
    userId: string | null,
    video: {
      blob: Blob | null;
      sha256: string | null;
      mime: string | null;
      path: string | null;
      size: number | null;
    },
  ) {
    const sessionId = result.session_id;
    const startedAt = session?.started_at ?? new Date(startedAtRef.current || Date.now()).toISOString();
    const endedAt = result.ended_at ?? new Date().toISOString();

    // Eventos encadeados da sessão (fonte da verdade no servidor).
    const { data: rows } = await supabase
      .from("sealed_capture_events")
      .select("seq,event_type,payload_sha256,prev_hash,event_hash,created_at")
      .eq("session_id", sessionId)
      .order("seq", { ascending: true });
    const events: SealedEventRecord[] = (rows ?? []) as SealedEventRecord[];

    const domLinks = integrity.domLinks;
    const artifacts: ArtifactEntry[] = [];
    const files: Array<{ file_name: string; blob: Blob }> = [];

    if (video.sha256 && video.size) {
      const fileName = `video-sessao.${mimeRef.current.ext}`;
      artifacts.push({
        kind: "video",
        file_name: fileName,
        storage_path: video.path,
        sha256: video.sha256,
        size_bytes: video.size,
        mime: video.mime,
        captured_at: endedAt,
        dom_chain_hash: integrity.lastDomChainHash,
        dom_seq: domLinks.length > 0 ? domLinks[domLinks.length - 1].seq : null,
        event_hash: events.length > 0 ? events[events.length - 1].event_hash : null,
        event_seq: events.length > 0 ? events[events.length - 1].seq : null,
        notes: "Gravação de tela da sessão lacrada, com hash calculado antes do envio.",
      });
      // Só conserva a mídia no pacote local quando o upload falhou. Após
      // persistência, o ZIP referencia o caminho privado e o SHA-256.
      if (!video.path && video.blob) files.push({ file_name: fileName, blob: video.blob });
    }

    const baseManifest: ArtifactManifest = {
      schema: "trace-hub/sealed-artifact-manifest",
      schema_version: "1.0",
      session_id: sessionId,
      target_url: result.target_url ?? targetUrl,
      operator_id: userId ?? "desconhecido",
      started_at: startedAt,
      ended_at: endedAt,
      timezone_offset_minutes: -new Date().getTimezoneOffset(),
      user_agent: navigator.userAgent,
      viewport: { width: window.innerWidth, height: window.innerHeight },
      event_chain: {
        count: events.length,
        merkle_root: result.merkle_root ?? null,
        genesis: "0".repeat(64),
      },
      dom_chain: {
        count: domLinks.length,
        final_chain_hash: integrity.lastDomChainHash,
        links: domLinks,
      },
      mutations_count: integrity.mutations.length,
      tamper: {
        detected: integrity.tamperDetected,
        methods: integrity.tamperMethods,
        events_count: integrity.tamperEvents.length,
      },
      payload_audit: integrity.payloadAudit,
      audio: { ...audioInfoRef.current },
      observation: {
        info: observation,
        surface_events: surfaceEvents,
        surface_anomaly: surfaceEvents.some(
          (e) => e.kind === "captured_surface_resize" || e.kind === "surface_switched",
        ),
      },
      video_integrity: {
        frame_chain_count: frameLinks.length,
        frame_chain_final_hash: frameLinks.length > 0 ? frameLinks[frameLinks.length - 1].chain_hash : null,
        sample_interval_ms: 1000,
        links: frameLinks,
      },
      artifacts,
      master_hash_algorithm: "SHA-256",
      master_hash_input: "canonical_json(manifest_without_master_hash)",
    };

    const manifest = await sealManifest(baseManifest);
    const audit = buildIntegrityAuditReport(manifest);

    // Persiste os artefatos JSON no depósito privado (pasta = id da sessão).
    const uploadJson = async (name: string, value: unknown) => {
      const path = `${sessionId}/${name}`;
      const { error } = await supabase.storage
        .from("sealed-artifacts")
        .upload(path, new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }), {
          contentType: "application/json",
          upsert: true,
        });
      return error ? null : path;
    };

    const [manifestPath, domPath, mutationsPath, auditPath, framesPath] = await Promise.all([
      uploadJson("manifest.json", manifest),
      uploadJson("cadeia_dom.json", { session_id: sessionId, links: domLinks }),
      uploadJson("mutacoes.json", { session_id: sessionId, mutations: integrity.mutations }),
      uploadJson("relatorio_auditoria.json", audit),
      uploadJson("cadeia_frames.json", { session_id: sessionId, links: frameLinks }),
    ]);
    void framesPath;

    await supabase.functions.invoke("sealed-session-package", {
      body: {
        session_id: sessionId,
        master_hash: manifest.master_hash,
        artifact_manifest: { ...manifest, dom_chain: { ...manifest.dom_chain, links: [] } },
        artifact_manifest_path: manifestPath,
        dom_chain_path: domPath,
        mutations_path: mutationsPath,
        audit_report_path: auditPath,
        environment_tampered: integrity.tamperDetected,
        forensic_status: audit.verdict,
      },
    });

    setPackageState({ manifest, audit, events, files });
  }




  async function handleDownloadPackage() {

    if (!packageState || buildingZip) return;
    setBuildingZip(true);
    try {
      // Vídeos muito grandes levam a aba ao limite de memória ao serem
      // embalados. Acima de 800 MB o pacote sai sem a mídia (que segue
      // baixável separadamente e com o hash declarado no manifesto).
      const MAX_MEDIA_IN_ZIP = 800 * 1024 * 1024;
      const heavy = packageState.files.filter((f) => f.blob.size > MAX_MEDIA_IN_ZIP);
      const files = packageState.files.filter((f) => f.blob.size <= MAX_MEDIA_IN_ZIP);
      if (heavy.length > 0) {
        toast.warning(
          "O vídeo é grande demais para entrar no ZIP com segurança. O pacote sai sem a mídia — baixe o vídeo pelo botão dedicado; o hash dele consta no manifesto.",
          { duration: 10000 },
        );
      }
      const zip = await buildSealedForensicPackage({
        manifest: packageState.manifest,
        audit: packageState.audit,
        domLinks: packageState.manifest.dom_chain.links,
        mutations: integrity.mutations,
        events: packageState.events,
        files,
        verifyUrl: `${window.location.origin}/verificar-sessao-lacrada`,
      });

      const url = URL.createObjectURL(zip);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pacote_integridade_sessao_${packageState.manifest.session_id}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 3000);
      toast.success("Pacote de integridade gerado");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Falha ao gerar o pacote");
    } finally {
      setBuildingZip(false);
    }
  }

  async function handleRetryUpload() {
    if (!done) return;
    const blob = recordedBlobRef.current;
    const { data: u } = await supabase.auth.getUser();
    const userId = u?.user?.id;
    const sessionId = done.session_id;
    if (!blob || !userId || !sessionId) {
      toast.error("Vídeo indisponível para reenvio. Refaça a captura.");
      return;
    }
    setRetryingUpload(true);
    try {
      const up = await uploadVideo(sessionId, userId, blob);
      if (!up) return;
      const updated: SealedFinalizeResult & SealedVideoMeta = {
        ...done,
        video_path: up.path,
        video_signed_url: up.signedUrl,
        video_bucket: "sealed-capture",
        video_signed_url_expires_at: up.expiresAt,
      };
      setDone(updated);
      setUploadFailed(false);
      recordedBlobRef.current = null;
      recordingResultRef.current = null;
      await recordingStoreRef.current?.discard().catch(() => undefined);
      recordingStoreRef.current = null;
      setPackageState((current) => {
        if (!current) return current;
        return {
          ...current,
          files: [],
          manifest: {
            ...current.manifest,
            artifacts: current.manifest.artifacts.map((artifact) =>
              artifact.kind === "video" ? { ...artifact, storage_path: up.path } : artifact,
            ),
          },
        };
      });
      try {
        channelRef.current?.postMessage({ type: "sealed-capture:finalized", payload: updated });
      } catch {
        /* noop */
      }
      try {
        window.opener?.postMessage({ type: "sealed-capture:finalized", payload: updated }, window.location.origin);
      } catch {
        /* noop */
      }
      toast.success("Vídeo enviado!");
    } finally {
      setRetryingUpload(false);
    }
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-lg border border-destructive/40 bg-destructive/10 p-6 text-sm space-y-3">
          <div className="flex items-center gap-2 text-destructive font-semibold">
            <AlertTriangle className="w-5 h-5" /> Erro ao iniciar Ambiente Lacrado
          </div>
          <p className="text-foreground/80">{error}</p>
          <Button variant="outline" onClick={() => window.close()} className="w-full">
            Fechar aba
          </Button>
        </div>
      </div>
    );
  }

  if (done) {
    const hasVideo = !!done.video_path;
    return (
      <div className="min-h-screen bg-background flex items-start justify-center p-6">
        <div className="max-w-xl w-full space-y-4">
          <div className="rounded-xl border border-primary/40 bg-primary/5 p-5 text-center space-y-2">
            <ShieldCheck className="w-10 h-10 text-primary mx-auto" />
            <h1 className="text-lg font-bold">Sessão lacrada e ancorada</h1>
            <p className="text-xs text-muted-foreground">
              Baixe o vídeo agora. Ele também fica disponível na Ata Notarial Digital por ~30 dias.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-3">
            <div className="flex items-center gap-2">
              <Hash className="w-4 h-4 text-primary" />
              <h3 className="text-sm font-bold">Pacote de integridade forense</h3>
              {packageState && (
                <Badge
                  variant={packageState.audit.verdict === "integra" ? "default" : "secondary"}
                  className="ml-auto text-[10px]"
                >
                  {packageState.audit.verdict === "integra"
                    ? "Íntegra"
                    : packageState.audit.verdict === "integra_com_ressalvas"
                      ? "Íntegra com ressalvas"
                      : "Comprometida"}
                </Badge>
              )}
            </div>
            {packageState ? (
              <>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-muted-foreground">
                  <span>Eventos encadeados: {packageState.audit.counters.events}</span>
                  <span>Snapshots de DOM: {packageState.audit.counters.dom_links}</span>
                  <span>Mutações registradas: {packageState.audit.counters.mutations}</span>
                  <span>Artefatos com hash: {packageState.audit.counters.artifacts}</span>
                </div>
                <p className="text-[10px] font-mono break-all text-muted-foreground">
                  Master Hash: {packageState.manifest.master_hash}
                </p>
                <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-3 text-[11px] space-y-1">
                  <p className="font-semibold text-amber-500 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" /> Escopo de observação da gravação: pixel-only
                  </p>
                  <p className="text-muted-foreground">{PIXEL_ONLY_WARNING}</p>
                  <p className="text-muted-foreground">
                    Frames amostrados e encadeados: {packageState.manifest.video_integrity?.frame_chain_count ?? 0}
                    {packageState.manifest.observation?.surface_anomaly
                      ? " — ANOMALIA: a superfície gravada mudou de tamanho ou foi trocada durante a coleta (indício de inspetor aberto na aba alvo)."
                      : " — nenhuma anomalia de superfície detectada."}
                  </p>
                </div>
                {integrity.tamperDetected && (
                  <p className="text-[11px] text-amber-500 flex items-start gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    Sinais de inspeção/adulteração do ambiente registrados na cadeia:{" "}
                    {integrity.tamperMethods.join(", ")}.
                  </p>
                )}
                <Button variant="outline" className="w-full" onClick={handleDownloadPackage} disabled={buildingZip}>
                  {buildingZip ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Download className="w-4 h-4 mr-2" />
                  )}
                  Baixar pacote de integridade (ZIP)
                </Button>
                <p className="text-[10px] text-muted-foreground text-center">
                  Anexo técnico de conferência: manifesto, relatório de auditoria, cadeias de eventos e de DOM, hashes e
                  instruções de verificação independente. O relatório para uso em juízo é o da Ata Notarial Digital.
                </p>

              </>
            ) : (
              <p className="text-[11px] text-muted-foreground flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Selando manifesto e ancorando o Master Hash…
              </p>
            )}
          </div>


          {hasVideo && (
            <div className="rounded-xl border-2 border-emerald-500/40 bg-emerald-500/5 p-4 space-y-3">
              <div className="flex items-start gap-3">
                <div className="w-12 h-12 rounded-full bg-emerald-500/15 flex items-center justify-center shrink-0">
                  <Video className="w-6 h-6 text-emerald-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-base font-bold">Seu vídeo está pronto</h3>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Salve no seu computador. Você pode rebaixar pela Ata Notarial depois.
                  </p>
                </div>
              </div>
              <Button
                size="lg"
                className="w-full bg-emerald-600 hover:bg-emerald-700 text-white text-base h-12"
                onClick={async () => {
                  try {
                    await downloadSealedVideo(done);
                    toast.success("Download iniciado!");
                  } catch (e) {
                    toast.error(e instanceof Error ? e.message : "Falha ao baixar vídeo");
                  }
                }}
              >
                <Download className="w-5 h-5 mr-2" />
                Baixar vídeo agora{formatMB(done.video_size) ? ` (${formatMB(done.video_size)})` : ""}
              </Button>
              <p className="text-[10px] text-muted-foreground text-center font-mono break-all">
                {buildFriendlyFilename(done)}
              </p>
              {done.video_sha256 && (
                <p className="text-[10px] text-muted-foreground text-center font-mono break-all">
                  SHA-256: {done.video_sha256.slice(0, 32)}…
                </p>
              )}
            </div>
          )}

          {!hasVideo && uploadFailed && recordedBlobRef.current && (
            <div className="rounded-xl border-2 border-amber-500/40 bg-amber-500/10 p-4 space-y-3">
              <div className="flex items-start gap-2 text-amber-200">
                <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-amber-400" />
                <div className="text-sm">
                  <strong>O envio do vídeo falhou.</strong> O arquivo ainda está em memória — tente reenviar ou baixar
                  localmente sem subir para o servidor.
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    const blob = recordedBlobRef.current;
                    if (!blob) {
                      toast.error("Vídeo indisponível");
                      return;
                    }
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `captura-lacrada-${Date.now()}.${mimeRef.current.ext}`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    setTimeout(() => URL.revokeObjectURL(url), 3000);
                  }}
                >
                  <Download className="w-4 h-4 mr-2" /> Baixar local
                </Button>
                <Button onClick={handleRetryUpload} disabled={retryingUpload}>
                  {retryingUpload ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
                  Tentar reenviar
                </Button>
              </div>
            </div>
          )}

          {!hasVideo && !uploadFailed && (
            <div className="rounded-xl border border-muted bg-muted/30 p-4 text-xs text-muted-foreground">
              {captureIssue ??
                "Nenhum vídeo foi salvo nessa sessão (você cancelou a gravação ou nenhuma mídia foi capturada)."}{" "}
              A sessão segue lacrada e ancorada por hash.
            </div>
          )}

          <div className="rounded-xl border border-border bg-card p-4 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Encerrada em</span>
              <span className="font-mono">{new Date(done.ended_at).toLocaleString("pt-BR")}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground flex items-center gap-1">
                <Hash className="w-3 h-3" />
                Eventos
              </span>
              <span className="font-mono">{done.event_count}</span>
            </div>
            <div>
              <p className="text-muted-foreground">Selo da sessão (Merkle root)</p>
              <p className="font-mono break-all text-[10px]">{done.merkle_root}</p>
            </div>
            {done.originstamp_id && (
              <div>
                <p className="text-muted-foreground flex items-center gap-1">
                  <Anchor className="w-3 h-3" />
                  Âncora blockchain
                </p>
                <p className="font-mono break-all text-[10px]">{done.originstamp_id}</p>
              </div>
            )}
          </div>

          <Button onClick={() => window.close()} variant="outline" className="w-full">
            <CheckCircle2 className="w-4 h-4 mr-2" /> Fechar aba
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <header className="px-4 py-2 border-b flex flex-wrap items-center gap-2 bg-muted/30 text-xs">
        <Badge variant="outline" className="gap-1">
          <ShieldCheck className="w-3 h-3" /> Ambiente Lacrado
        </Badge>
        {session && (
          <>
            <Badge variant="outline" className="gap-1">
              <Globe className="w-3 h-3" />
              {(() => {
                try {
                  return new URL(session.target_url).hostname;
                } catch {
                  return session.target_url;
                }
              })()}
            </Badge>
            <Badge variant="outline" className="gap-1">
              <Hash className="w-3 h-3" />
              {eventCount} eventos
            </Badge>
            <Badge variant="outline">{formatTimer(elapsed)}</Badge>
          </>
        )}
        {recording && mediaReady && (
          <Badge className="gap-1 bg-red-500/15 text-red-400 border-red-500/40">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" /> REC
          </Badge>
        )}
        {recording && !mediaReady && streamConnected && (
          <Badge className="gap-1 bg-sky-500/15 text-sky-300 border-sky-500/40">
            <Loader2 className="w-3 h-3 animate-spin" /> Conectado — aguardando frames
          </Badge>
        )}
        {recording && !mediaReady && !streamConnected && (
          <Badge className="gap-1 bg-amber-500/15 text-amber-300 border-amber-500/40">
            <Loader2 className="w-3 h-3 animate-spin" /> Conectando à aba…
          </Badge>
        )}
        {recording && audioLevel && (
          <Badge
            variant="outline"
            className={`gap-1.5 ${audioSilentAlert ? "border-amber-500/50 text-amber-300" : "border-emerald-500/40 text-emerald-300"}`}
            title={
              audioSilentAlert
                ? "Silêncio absoluto — confirme o compartilhamento do áudio da aba"
                : "Nível de áudio capturado"
            }
          >
            {audioSilentAlert ? <VolumeX className="w-3 h-3" /> : <Volume2 className="w-3 h-3" />}
            <span className="inline-flex h-1.5 w-16 overflow-hidden rounded bg-muted">
              <span
                className={`h-full ${audioSilentAlert ? "bg-amber-400" : "bg-emerald-400"}`}
                style={{ width: `${Math.min(100, Math.round(audioLevel.level * 400))}%` }}
              />
            </span>
          </Badge>
        )}
        {recording && !audioLevel && audioInfoRef.current.tracks === 0 && (
          <Badge variant="outline" className="gap-1 border-amber-500/50 text-amber-300">
            <VolumeX className="w-3 h-3" /> sem áudio
          </Badge>
        )}
        {!recording && (
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
            <input
              type="checkbox"
              className="accent-primary"
              checked={includeMic}
              onChange={(e) => setIncludeMic(e.target.checked)}
            />
            <Mic className="w-3 h-3" /> Incluir microfone (narração)
          </label>
        )}
        <div className="ml-auto flex gap-2">
          {!recording ? (
            <Button
              size="sm"
              variant={iframeLoaded && recordPref ? "default" : "outline"}
              onClick={() => startRecording()}
              disabled={!iframeLoaded || pickerArmed}
              title={!iframeLoaded ? "Aguarde a página carregar" : "Gravar tela — escolha a aba real do site alvo"}
            >
              {pickerArmed ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Video className="w-3 h-3 mr-1" />}
              {recordedBlobRef.current ? "Vídeo pronto" : "Gravar tela"}
            </Button>
          ) : (
            <Button
              size="sm"
              variant="outline"
              disabled={closingVideo}
              onClick={async () => {
                const blob = await stopRecording();
                if (blob && blob.size > 0) {
                  toast.success('Vídeo preparado. Clique em "Encerrar & lacrar" para enviar.');
                } else {
                  toast.warning(captureIssue ?? "O navegador não gerou um arquivo de vídeo nesta tentativa.");
                }
              }}
            >
              {closingVideo ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <VideoOff className="w-3 h-3 mr-1" />}
              {closingVideo ? "Preparando vídeo…" : "Parar gravação"}
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={handleScreenshot} disabled={!session}>
            <Camera className="w-3 h-3 mr-1" /> Marcar
          </Button>
          <Button
            size="sm"
            variant="destructive"
            onClick={handleFinalize}
            disabled={finalizing || uploadingVideo || !session}
          >
            {finalizing || uploadingVideo || closingVideo ? (
              <Loader2 className="w-3 h-3 mr-1 animate-spin" />
            ) : (
              <Square className="w-3 h-3 mr-1" />
            )}
            {uploadingVideo
              ? `Enviando vídeo… ${uploadProgress}%`
              : finalizationPhase ?? (closingVideo ? "Preparando vídeo…" : "Encerrar & lacrar")}
          </Button>
        </div>
      </header>

      <AlertDialog open={noAudioPrompt} onOpenChange={setNoAudioPrompt}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <VolumeX className="w-4 h-4 text-amber-400" /> A fonte foi compartilhada sem áudio
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2 text-left">
                <p>
                  A gravação não foi iniciada porque o navegador não entregou nenhuma trilha de áudio. Em páginas com
                  som (YouTube, reuniões, vídeos de redes sociais) isso torna a prova incompleta.
                </p>
                <p className="text-foreground">
                  No seletor do navegador, escolha a aba <strong>Aba do Chrome/Edge</strong>, selecione a aba do alvo e
                  marque <strong>Compartilhar áudio da aba</strong> no canto inferior da janela antes de confirmar.
                </p>
                <p className="text-xs">
                  Compartilhar “Tela inteira” só captura som do sistema no Windows; “Janela” normalmente não captura
                  áudio nenhum.
                </p>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => {
                setNoAudioPrompt(false);
                void startRecording({ allowNoAudio: true });
              }}
            >
              Gravar sem áudio (assumo a limitação)
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                setNoAudioPrompt(false);
                void startRecording();
              }}
            >
              Escolher fonte novamente
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {recordPref && !recording && !recordedBlobRef.current && !pickerArmed && iframeLoaded && (
        <div className="px-4 py-2 bg-primary/15 border-b text-xs text-primary flex items-center gap-2 animate-pulse">
          <Video className="w-3.5 h-3.5" />
          Abra o site alvo em outra janela ou navegador, clique em <strong>Gravar tela</strong> e escolha{" "}
          <strong>{socialMode ? "a aba da rede social" : "a aba real do site alvo"}</strong> no seletor do navegador.
          Para capturar som, ative <strong>Compartilhar áudio</strong> quando essa opção aparecer.
          {!socialMode && (
            <Button size="sm" variant="outline" className="h-7 ml-auto" onClick={openTargetTab}>
              Abrir alvo
            </Button>
          )}
        </div>
      )}

      {recordPref && pickerArmed && (
        <div className="px-4 py-2 bg-primary/10 border-b text-xs text-primary flex items-center gap-2">
          <Loader2 className="w-3 h-3 animate-spin" />
          {socialMode ? (
            <>
              O navegador vai pedir para escolher a tela — selecione{" "}
              <strong>a aba da rede social onde você está logado</strong> (NÃO esta aba).
            </>
          ) : (
            <>
              O navegador vai pedir para escolher a tela — selecione <strong>a aba real do site alvo</strong>, não esta
              aba lacrada.
            </>
          )}
        </div>
      )}

      {recordPref && !recording && !pickerArmed && iframeLoaded && (
        <div className="px-4 py-2 bg-amber-500/10 border-b text-xs text-amber-200 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            Se a aba alvo não aparecer no seletor, abra o site em <strong>outro navegador</strong> ou em uma{" "}
            <strong>janela separada</strong> e selecione essa janela/aba. Alguns navegadores não listam abas do mesmo
            navegador quando a captura foi iniciada pela aba lacrada. Para áudio de vídeos, use o ambiente lacrado no{" "}
            <strong>Chrome/Edge</strong>, abra o alvo em outra janela do mesmo navegador, selecione a aba do alvo e
            marque <strong>Compartilhar áudio</strong>.
          </div>
        </div>
      )}

      {recording && !mediaReady && (
        <div className="px-4 py-2 bg-amber-500/10 border-b text-xs text-amber-200 flex items-center gap-2">
          <Loader2 className="w-3 h-3 animate-spin" />
          {streamConnected ? (
            <>
              Aba conectada — esperando os primeiros frames renderizarem. Mantenha a aba alvo visível e{" "}
              <strong>não pare agora</strong>.
            </>
          ) : (
            <>Conectando à aba selecionada…</>
          )}
        </div>
      )}

      {socialMode && (
        <div className="px-4 py-3 bg-amber-500/10 border-b text-xs text-amber-200 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-bold">Modo Rede Social — leia antes de gravar</p>
            <p>
              1) Abra a postagem em outra aba e faça login. 2) Volte aqui e clique em <strong>Gravar tela</strong>. 3)
              No diálogo do navegador, escolha a aba da rede social (não esta). 4) Quando terminar, volte aqui e clique
              em <strong>Encerrar &amp; lacrar</strong>. Para capturar som, marque <strong>Compartilhar áudio</strong>{" "}
              no seletor do navegador quando a opção estiver disponível.
            </p>
            <Button
              size="sm"
              variant="outline"
              className="mt-1 h-7 border-amber-400 text-amber-200 hover:bg-amber-500/10"
              onClick={() => {
                try {
                  window.open(targetUrl, "_blank", "noopener");
                } catch {
                  /* noop */
                }
              }}
            >
              Abrir postagem para login
            </Button>
          </div>
        </div>
      )}

      <main className="flex-1 relative bg-background">
        {socialMode ? (
          <div className="absolute inset-0 flex items-center justify-center p-8">
            <div className="max-w-lg w-full rounded-xl border-2 border-primary/30 bg-primary/5 p-6 text-sm space-y-3 text-center">
              <ShieldCheck className="w-10 h-10 text-primary mx-auto" />
              <h2 className="text-base font-bold">Pronto para gravar a aba logada</h2>
              <p className="text-muted-foreground">
                Esta janela não exibe a rede social — ela só grava, hasheia e lacra a aba que você selecionar no diálogo
                de compartilhamento. Faça login na outra aba e clique em <strong>Gravar tela</strong> acima.
              </p>
              <div className="text-[11px] text-muted-foreground border-t border-primary/20 pt-3">
                Alvo: <span className="font-mono break-all">{targetUrl}</span>
              </div>
            </div>
          </div>
        ) : (
          <>
            {!iframeSrc && (
              <div className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
                <Loader2 className="w-5 h-5 animate-spin mr-2" /> Iniciando sessão lacrada…
              </div>
            )}
            {iframeSrc && !iframeLoaded && (
              <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground pointer-events-none">
                <Loader2 className="w-4 h-4 animate-spin mr-2" /> Carregando alvo no proxy lacrado…
              </div>
            )}
            {iframeSrc && (
              <iframe
                ref={iframeRef}
                src={iframeSrc}
                title="Sealed Capture Viewer"
                className="w-full h-full border-0"
                sandbox="allow-scripts allow-forms allow-popups allow-same-origin"
                referrerPolicy="no-referrer"
                onLoad={() => setIframeLoaded(true)}
              />
            )}
          </>
        )}
      </main>
    </div>
  );
}

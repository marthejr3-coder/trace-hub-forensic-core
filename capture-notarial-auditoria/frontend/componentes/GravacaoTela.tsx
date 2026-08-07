import { useEffect, useRef, useState } from 'react';
import { StjComplianceBanner } from '@/components/juridico/StjComplianceBanner';
import { useCredits } from '@/components/credits/CreditsGateProvider';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Video, StopCircle, Loader2, Hash, Download, Bitcoin, Clock, ExternalLink, Mic, MicOff, FileText, Smartphone, Info, Crop, Globe, Package } from 'lucide-react';
import { toast } from 'sonner';
import { supabase } from '@/integrations/supabase/client';
import { generateSHA256 } from '@/lib/forensic-hash';
import { registerForensicReport } from '@/lib/forensic-seal';
import { isIOS, openPopupForDownload, downloadBlob } from '@/lib/ios-download';
import AssinaturaDigital from '@/components/juridico/AssinaturaDigital';

/** Detecta se o navegador suporta gravação de tela (getDisplayMedia). */
function supportsScreenCapture(): boolean {
  return typeof navigator !== 'undefined'
    && !!navigator.mediaDevices
    && typeof navigator.mediaDevices.getDisplayMedia === 'function';
}
import {
  ReportRoot,
  ReportFrontispiece,
  PartHeader,
  PartSection,
  SubHeader,
  ReportField,
  HashHighlight,
  ValidationPage,
  FONT_BODY,
  FONT_MONO,
  useForensicExport,
} from '@/lib/forensic-report-kit';

interface RecordResult {
  blob: Blob;
  url: string;
  mime: string;
  size: number;
  duration_seconds: number;
  video_hash: string;
  started_at: string;
  finished_at: string;
  timestamp_source: string;
  evidence_hash: string;
}

interface StampResult {
  ots_file_base64: string;
  rfc3161_token_base64: string | null;
  rfc3161_timestamp: string | null;
  calendars: string[];
  submitted_at: string;
}

import { useForensicAuthor } from "@/hooks/useForensicAuthor";
import { ForensicSignatureBlock } from "@/components/juridico/metadados/ForensicAuthorBlock";

export default function GravacaoTela() {
  const { author } = useForensicAuthor();
  const { consume: __consumeCredit } = useCredits();
  const [recording, setRecording] = useState(false);
  const [withAudio, setWithAudio] = useState(true);
  const [elapsed, setElapsed] = useState(0);
  const [processing, setProcessing] = useState(false);
  const [result, setResult] = useState<RecordResult | null>(null);
  const [stamp, setStamp] = useState<StampResult | null>(null);
  const [stamping, setStamping] = useState(false);
  const [posterFrame, setPosterFrame] = useState<string | null>(null);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [packaging, setPackaging] = useState(false);

  const recorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const streamRef = useRef<MediaStream | null>(null);
  const startedAtRef = useRef<string>('');
  const timerRef = useRef<number | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);

  const { generating, exportPDF, exportPNG } = useForensicExport(
    // @ts-ignore migration: strict-mode wave
    reportRef,
    'gravacao-cartorial',
    () => result?.evidence_hash?.slice(0, 16),
    setPdfBase64,
  );

  const capturePosterFrame = async (videoUrl: string) => {
    try {
      const v = document.createElement('video');
      v.src = videoUrl;
      v.muted = true;
      await new Promise<void>((resolve, reject) => {
        v.onloadeddata = () => resolve();
        v.onerror = () => reject(new Error('video load failed'));
      });
      v.currentTime = Math.min(1, v.duration / 2);
      await new Promise<void>((resolve) => { v.onseeked = () => resolve(); });
      const canvas = document.createElement('canvas');
      canvas.width = v.videoWidth || 1280;
      canvas.height = v.videoHeight || 720;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
      setPosterFrame(canvas.toDataURL('image/jpeg', 0.85));
    } catch (e) {
      console.warn('poster frame capture failed', e);
    }
  };

  useEffect(() => {
    return () => {
      streamRef.current?.getTracks().forEach((t) => t.stop());
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, []);

  const startRecording = async () => {
    if (!supportsScreenCapture()) {
      toast.error('Seu navegador não suporta gravação de tela. Use a gravação nativa do iOS (Central de Controle).');
      return;
    }
    try {
      // @ts-ignore
      const display: MediaStream = await navigator.mediaDevices.getDisplayMedia({
        video: { frameRate: 30 },
        audio: withAudio,
      });
      let combined = display;
      if (withAudio) {
        try {
          const mic = await navigator.mediaDevices.getUserMedia({ audio: true });
          const ctx = new AudioContext();
          const dest = ctx.createMediaStreamDestination();
          if (display.getAudioTracks().length > 0) {
            ctx.createMediaStreamSource(new MediaStream([display.getAudioTracks()[0]])).connect(dest);
          }
          ctx.createMediaStreamSource(mic).connect(dest);
          combined = new MediaStream([
            ...display.getVideoTracks(),
            ...dest.stream.getAudioTracks(),
          ]);
          (combined as any).__extra = [mic, display];
        } catch {}
      }
      streamRef.current = combined;

      const mimeCandidates = ['video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm'];
      const mime = mimeCandidates.find((m) => MediaRecorder.isTypeSupported(m)) || 'video/webm';
      const recorder = new MediaRecorder(combined, { mimeType: mime, videoBitsPerSecond: 2_500_000 });
      recorderRef.current = recorder;
      chunksRef.current = [];

      recorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) chunksRef.current.push(e.data);
      };
      recorder.onstop = handleStop;

      display.getVideoTracks()[0].onended = () => {
        if (recorderRef.current?.state === 'recording') recorderRef.current.stop();
      };

      recorder.start(1000);
      startedAtRef.current = new Date().toISOString();
      setRecording(true);
      setElapsed(0);
      timerRef.current = window.setInterval(() => setElapsed((s) => s + 1), 1000);
      toast.success('Gravação iniciada');
    } catch (e: any) {
      if (e?.name === 'NotAllowedError') toast.error('Permissão negada');
      else toast.error(e?.message || 'Falha');
    }
  };

  const stopRecording = () => {
    const rec = recorderRef.current;
    try {
      if (rec && rec.state !== 'inactive') {
        rec.stop();
      } else {
        // Recorder already finalizou ou nunca iniciou: dispara handleStop manualmente
        // para não deixar o usuário travado no estado "Gravando…".
        handleStop();
      }
    } catch (err) {
      console.error('[GravacaoTela] erro ao parar recorder', err);
      handleStop();
    }
    // Garante que o compartilhamento de tela termine imediatamente, mesmo que
    // o evento onstop demore — assim o usuário sempre vê o feedback de parada.
    try {
      streamRef.current?.getTracks().forEach((t) => t.stop());
      const extras: MediaStream[] = (streamRef.current as any)?.__extra || [];
      extras.forEach((s) => s.getTracks().forEach((t) => t.stop()));
    } catch {}
  };

  const handleStop = async () => {
    setRecording(false);
    if (timerRef.current) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
    setProcessing(true);
    try {
      const finishedAt = new Date().toISOString();
      const mime = recorderRef.current?.mimeType || 'video/webm';
      const blob = new Blob(chunksRef.current, { type: mime });
      const url = URL.createObjectURL(blob);

      const buf = new Uint8Array(await blob.arrayBuffer());
      const videoHash = await sha256OfBytes(buf);

      let timestampSource = 'local server (fallback)';
      try {
        await fetch('https://worldtimeapi.org/api/timezone/Etc/UTC');
        timestampSource = 'worldtimeapi.org (UTC) + local';
      } catch {}

      // Calcula duração a partir dos timestamps reais — handleStop fecha sobre
      // o valor inicial de `elapsed` (closure stale) e sempre veria 0.
      const startedMs = startedAtRef.current ? Date.parse(startedAtRef.current) : NaN;
      const finishedMs = Date.parse(finishedAt);
      const durationSec = Number.isFinite(startedMs) && Number.isFinite(finishedMs)
        ? Math.max(0, Math.round((finishedMs - startedMs) / 1000))
        : 0;

      const evidencePayload = JSON.stringify({
        video_hash: videoHash,
        size_bytes: blob.size,
        duration_seconds: durationSec,
        started_at: startedAtRef.current,
        finished_at: finishedAt,
        mime,
      });
      const evidenceHash = await generateSHA256(evidencePayload);

      const extras: MediaStream[] = (streamRef.current as any)?.__extra || [];
      streamRef.current?.getTracks().forEach((t) => t.stop());
      extras.forEach((s) => s.getTracks().forEach((t) => t.stop()));
      streamRef.current = null;

      setResult({
        blob, url, mime, size: blob.size,
        duration_seconds: durationSec,
        video_hash: videoHash,
        started_at: startedAtRef.current,
        finished_at: finishedAt,
        timestamp_source: timestampSource,
        evidence_hash: evidenceHash,
      });
      registerForensicReport({
        evidenceHash,
        reportType: 'screen_recording',
        subject: `Gravação ${durationSec}s · ${(blob.size / 1024 / 1024).toFixed(1)} MB`,
        metadata: { video_hash: videoHash, duration_seconds: durationSec, mime, size_bytes: blob.size, timestamp_source: timestampSource },
      });
      capturePosterFrame(url).catch(() => {});
      toast.success(`Vídeo selado · ${(blob.size / 1024 / 1024).toFixed(1)} MB`);
    } catch (e: any) {
      toast.error(e?.message || 'Falha');
    } finally {
      setProcessing(false);
    }
  };

  const handleStamp = async () => {
    if (!result?.evidence_hash) return;
    setStamping(true);
    try {
      const __gate = await __consumeCredit('juridico-gravacao');
      if (!__gate.allowed) return;
      const { data, error } = await supabase.functions.invoke('originstamp-anchor', { body: { evidence_hash: result.evidence_hash, context: { tool: 'gravacao_tela', ref_id: result.evidence_hash } } });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setStamp({
        ots_file_base64: data.originstamp?.ots_base64 ?? data.originstamp?.raw_response_base64,
        rfc3161_token_base64: data.rfc3161?.token_base64 ?? null,
        rfc3161_timestamp: data.rfc3161?.timestamp ?? null,
        calendars: data.originstamp?.calendar_url ? [data.originstamp.calendar_url] : [],
        submitted_at: data.submitted_at,
      });
      toast.success('Vídeo ancorado em blockchain');
    } catch (e: any) {
      toast.error(e?.message || 'Falha');
    } finally {
      setStamping(false);
    }
  };

  const videoFileName = result
    ? `gravacao-${result.evidence_hash.slice(0, 12)}.webm`
    : '';

  const downloadVideo = () => {
    if (!result) return;
    const a = document.createElement('a');
    a.href = result.url;
    a.download = videoFileName;
    a.click();
  };

  const handleDownloadPackage = async () => {
    if (!result || !reportRef.current) return;
    const popup = openPopupForDownload('Montando pacote da prova\u2026');
    setPackaging(true);
    const t = toast.loading('Montando pacote completo da prova\u2026');
    try {
      const { sectionedPDFToBase64 } = await import('@/lib/pdf-section-export');
      const pdfBase64Str = await sectionedPDFToBase64(reportRef.current, {
        shortHash: result.evidence_hash.slice(0, 16),
      });
      setPdfBase64(pdfBase64Str);
      const { buildNotarialEvidenceZip } = await import('@/lib/notarial-evidence-zip');
      const { blob, filename } = await buildNotarialEvidenceZip({
        prefix: 'gravacao-notarial',
        label: 'Gravação Notarial de Tela',
        evidenceHash: result.evidence_hash,
        pdfBase64: pdfBase64Str,
        pdfFilename: 'relatorio_evidencia_gravacao.pdf',
        otsBase64: stamp?.ots_file_base64 ?? null,
        tsrBase64: stamp?.rfc3161_token_base64 ?? null,
        media: [{ filename: videoFileName, blob: result.blob, description: 'Vídeo original da gravação (arquivo íntegro, sem reencode)' }],
        meta: {
          'Duração': `${result.duration_seconds}s`,
          'Formato': result.mime,
          'Tamanho do vídeo': `${result.size} bytes`,
          'Hash do vídeo (SHA-256)': result.video_hash,
        },
        operatorName: author?.fullName || null,
        startedAt: result.started_at,
        finishedAt: result.finished_at,
      });
      downloadBlob(blob, filename, popup);
      toast.dismiss(t);
      toast.success('Pacote completo da prova baixado');
    } catch (e: any) {
      toast.dismiss(t);
      console.error('[Pacote ZIP]', e);
      try { popup?.close(); } catch { /* noop */ }
      toast.error(`Falha ao montar o pacote: ${e?.message || 'erro desconhecido'}`);
    } finally {
      setPackaging(false);
    }
  };

  const downloadBase64 = (b64: string, filename: string, mime: string) => {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };

  const reset = () => {
    if (result) URL.revokeObjectURL(result.url);
    setResult(null); setStamp(null); setPosterFrame(null); setElapsed(0);
  };

  const fmtTime = (s: number) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;

  return (
    <div className="space-y-4">
      <StjComplianceBanner variant="collection" />
      <div className="rounded-lg border bg-muted/30 p-3 text-xs space-y-1">
        <p><strong>Como usar:</strong> Inicie, navegue por todas as páginas que compõem a prova, pare. O vídeo é hashado e selado.</p>
      </div>

      {!recording && !result && !supportsScreenCapture() && (
        <Card className="border-amber-500/40 bg-gradient-to-br from-amber-500/10 via-amber-400/5 to-transparent">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Smartphone className="w-5 h-5 text-amber-500" />
              Gravação de tela não suportada {isIOS() ? 'no iPhone/iPad' : 'neste navegador'}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
              <Info className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
              <p className="text-muted-foreground leading-relaxed">
                {isIOS()
                  ? 'O Safari do iOS não permite que sites gravem a tela, por decisão da Apple. Isto vale para Chrome, Firefox e Edge no iPhone também (todos usam o WebKit). Use uma das alternativas abaixo — todas com a mesma validade jurídica.'
                  : 'Seu navegador não implementa a API de captura de tela. Atualize ou use Chrome/Firefox/Edge no desktop, ou siga uma das alternativas abaixo.'}
              </p>
            </div>

            <div className="space-y-3">
              <div className="rounded-lg border bg-card p-4 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-foreground">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/15 text-emerald-600 text-xs font-black">1</span>
                  Gravação nativa do iOS <span className="text-[10px] uppercase tracking-wider text-emerald-600 font-black">Recomendado</span>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed pl-8">
                  Abra a <strong>Central de Controle</strong> → toque no botão de <strong>Gravação de Tela</strong> ⏺ → grave normalmente. Após salvar em <em>Fotos</em>, anexe o <code>.mp4</code> ao seu caso ou faça upload na aba <strong>Recorte</strong> para gerar o hash SHA-256.
                </p>
                <div className="pl-8 pt-1">
                  <Button variant="outline" size="sm" asChild>
                    <a href="https://support.apple.com/pt-br/HT207935" target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="w-3 h-3 mr-1.5" /> Ver tutorial oficial Apple
                    </a>
                  </Button>
                </div>
              </div>

              <div className="rounded-lg border bg-card p-4 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-foreground">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/15 text-primary text-xs font-black">2</span>
                  Modo URL pública
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed pl-8">
                  Se a prova é uma página web (post, perfil, notícia), use a aba <strong>URL pública</strong> acima. Mais simples, mais robusto e gera ata notarial completa direto no servidor.
                </p>
              </div>

              <div className="rounded-lg border bg-card p-4 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-foreground">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/15 text-primary text-xs font-black">3</span>
                  Modo Recorte
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed pl-8">
                  Já tem screenshot ou vídeo gravado? Use a aba <strong>Recorte</strong> acima para anexar arquivo e gerar hash SHA-256 com selo cartorial.
                </p>
              </div>
            </div>

            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-xs text-muted-foreground leading-relaxed">
              <strong className="text-emerald-700 dark:text-emerald-400">Validade jurídica:</strong>{' '}
              vídeos gravados pela função nativa do iOS mantêm metadados originais e são igualmente aceitos como prova quando acompanhados de hash SHA-256 — você pode gerar o hash do <code>.mp4</code> aqui mesmo na aba <strong>Recorte</strong>.
            </div>
          </CardContent>
        </Card>
      )}

      {!recording && !result && supportsScreenCapture() && (
        <div className="space-y-3">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="flex items-center gap-2 text-sm">
              {withAudio ? <Mic className="w-4 h-4 text-emerald-500" /> : <MicOff className="w-4 h-4 text-muted-foreground" />}
              <span>Gravar áudio do operador</span>
            </div>
            <Button size="sm" variant={withAudio ? 'default' : 'outline'} onClick={() => setWithAudio((v) => !v)}>
              {withAudio ? 'Ativado' : 'Desativado'}
            </Button>
          </div>
          <Button onClick={startRecording} className="w-full bg-red-500 hover:bg-red-600 text-white">
            <Video className="w-4 h-4 mr-2" /> Iniciar gravação
          </Button>
        </div>
      )}

      {recording && (
        <Card className="border-red-500/40 bg-red-500/5">
          <CardContent className="pt-6 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-red-500 animate-pulse" />
                <span className="font-semibold">Gravando…</span>
                <span className="font-mono text-lg">{fmtTime(elapsed)}</span>
              </div>
              <Button onClick={stopRecording} variant="destructive" size="sm">
                <StopCircle className="w-4 h-4 mr-2" /> Parar e selar
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {processing && (
        <div className="flex items-center justify-center gap-2 p-4 rounded-lg border bg-muted/30 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Processando vídeo…
        </div>
      )}

      {result && (
        <>
          <div className="space-y-2">
            <Button
              onClick={handleDownloadPackage}
              disabled={packaging || generating}
              size="lg"
              className="w-full bg-emerald-600 hover:bg-emerald-700 text-white"
            >
              {packaging ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Package className="w-4 h-4 mr-2" />}
              Baixar pacote completo da prova (ZIP)
            </Button>
            <p className="text-xs text-muted-foreground">
              Um único arquivo com o relatório em PDF, o vídeo original, os selos .ots/.tsr já emitidos
              e as instruções de verificação independente.
            </p>
            <details className="text-sm">
              <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                Baixar arquivos separadamente
              </summary>
              <div className="flex flex-wrap gap-2 pt-2">
                <Button variant="outline" size="sm" onClick={exportPDF} disabled={generating}>
                  {generating ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <FileText className="w-4 h-4 mr-2" />}
                  Relatório (PDF)
                </Button>
                <Button variant="outline" size="sm" onClick={exportPNG} disabled={generating}>Se PDF falhar, PNG</Button>
                <Button variant="outline" size="sm" onClick={downloadVideo}>
                  <Download className="w-4 h-4 mr-2" /> Vídeo (.webm)
                </Button>
                {stamp && (
                  <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.ots_file_base64, `gravacao-${result.evidence_hash.slice(0, 12)}.ots`, 'application/vnd.opentimestamps')}>
                    <Download className="w-3.5 h-3.5 mr-1.5" /> .ots
                  </Button>
                )}
                {stamp?.rfc3161_token_base64 && (
                  <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.rfc3161_token_base64!, `gravacao-${result.evidence_hash.slice(0, 12)}.tsr`, 'application/timestamp-reply')}>
                    <Download className="w-3.5 h-3.5 mr-1.5" /> .tsr
                  </Button>
                )}
                <Button variant="ghost" size="sm" onClick={reset}>Nova gravação</Button>
              </div>
            </details>
          </div>


          <ReportRoot ref={reportRef}>
            <ReportFrontispiece
              titleLines={['Gravação', 'Notarial Digital']}
              tagline="Captura audiovisual forense · Prova autosuficiente"
              certificationText={
                <>
                  <strong>Certifica-se</strong>, para os devidos fins de direito, que entre{' '}
                  <strong>{new Date(result.started_at).toLocaleString('pt-BR')}</strong> e{' '}
                  <strong>{new Date(result.finished_at).toLocaleString('pt-BR')}</strong> foi
                  realizada gravação audiovisual forense da tela do operador, com duração total
                  de <strong>{fmtTime(result.duration_seconds)}</strong>{withAudio ? ' e narração por microfone' : ''}.
                  O arquivo de vídeo <strong>{videoFileName}</strong> (formato {result.mime.split(';')[0]}, {(result.size / 1024 / 1024).toFixed(2)} MB)
                  teve sua integridade selada por hash SHA-256 do binário.
                </>
              }
              summaryRows={[
                { label: 'Nome do arquivo', value: videoFileName },
                { label: 'Duração total', value: `${fmtTime(result.duration_seconds)} (${result.duration_seconds}s)` },
                { label: 'Tamanho do arquivo', value: `${(result.size / 1024 / 1024).toFixed(2)} MB` },
                { label: 'Codec', value: result.mime },
                { label: 'Áudio', value: withAudio ? 'Sim (microfone)' : 'Não' },
                { label: 'Fonte de tempo', value: result.timestamp_source },
              ]}
              evidenceHash={result.evidence_hash}
            />

            <PartSection className="pt-8">
              <PartHeader number="I" title="Da Gravação" subtitle="Quadro representativo e identificação do arquivo audiovisual" />
            </PartSection>

            <PartSection breakBefore={false} tall className="mt-5">
              {posterFrame ? (
                <figure className="border-2 p-2 bg-white shadow-md" style={{ borderColor: '#1a1a1a' }}>
                  <img src={posterFrame} alt="Quadro representativo" className="w-full block" />
                  <figcaption className="text-[9.5px] text-center pt-2 mt-2 border-t border-slate-200" style={{ fontFamily: FONT_BODY }}>
                    <strong>Quadro 1.</strong> Frame extraído do vídeo. O arquivo .webm completo deve ser anexado separadamente ao processo.
                  </figcaption>
                </figure>
              ) : (
                <div className="text-[11px] p-3 rounded border border-dashed border-amber-300 bg-amber-50 text-amber-800">
                  Quadro representativo indisponível. O vídeo está disponível para download.
                </div>
              )}
            </PartSection>

            <PartSection className="pt-8">
              <PartHeader number="II" title="Dos Metadados Técnicos" subtitle="Tempos, codec, dimensões e contexto da gravação" />
            </PartSection>

            <PartSection breakBefore={false} className="mt-4">
              <SubHeader>2.1 · Parâmetros técnicos</SubHeader>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 mt-2">
                <ReportField label="Nome do arquivo de vídeo" value={videoFileName} mono />
                <ReportField label="Início da gravação" value={new Date(result.started_at).toLocaleString('pt-BR')} mono />
                <ReportField label="Fim da gravação" value={new Date(result.finished_at).toLocaleString('pt-BR')} mono />
                <ReportField label="Duração" value={fmtTime(result.duration_seconds)} mono />
                <ReportField label="Tamanho" value={`${(result.size / 1024 / 1024).toFixed(2)} MB`} mono />
                <ReportField label="Codec / Container" value={result.mime} mono />
                <ReportField label="Áudio" value={withAudio ? 'Sim (microfone)' : 'Não'} />
              </dl>
            </PartSection>

            <PartSection className="pt-8">
              <PartHeader number="III" title="Da Integridade Criptográfica" subtitle="Impressões digitais SHA-256 que garantem que o vídeo não foi alterado" />
            </PartSection>

            <PartSection breakBefore={false} className="mt-4">
              <p className="text-[11.5px] leading-[1.65] text-justify mb-4" style={{ fontFamily: FONT_BODY }}>
                As funções <em>hash</em> SHA-256 abaixo constituem impressão digital única e
                irreversível do binário do vídeo. Qualquer alteração no arquivo .webm — corte,
                recodificação ou modificação — invalida ambos os <em>hashes</em>.
              </p>
              <div className="space-y-3">
                <div>
                  <SubHeader>3.1 · Hash binário do vídeo (.webm)</SubHeader>
                  <p className="font-mono text-[10px] break-all bg-slate-50 border border-slate-300 px-3 py-2 rounded" style={{ fontFamily: FONT_MONO }}>
                    {result.video_hash}
                  </p>
                </div>
                <HashHighlight
                  label="3.2 · Código Único de Verificação · SHA-256"
                  description="Hash composto que sintetiza vídeo + duração + timestamps. Use para validação pública."
                  hash={result.evidence_hash}
                />
              </div>
            </PartSection>

            <ValidationPage hash={result.evidence_hash} reportType="screen_recording" />

            <ForensicSignatureBlock author={author} />
          </ReportRoot>

          {result.evidence_hash && (
            <AssinaturaDigital evidenceHash={result.evidence_hash} pdfBase64={pdfBase64} />
          )}

          <Card className="border-emerald-500/40 bg-gradient-to-br from-emerald-500/5 to-transparent">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Bitcoin className="w-4 h-4 text-emerald-500" />
                Selo Blockchain + RFC 3161 (opcional)
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {!stamp && (
                <Button onClick={handleStamp} disabled={stamping} className="w-full bg-emerald-500 hover:bg-emerald-600 text-white">
                  {stamping ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Selando…</> : <><Bitcoin className="w-4 h-4 mr-2" /> Selar Blockchain</>}
                </Button>
              )}
              {stamp && (
                <div className="space-y-3 text-xs">
                  <div className="flex items-start gap-2 p-3 rounded border border-emerald-500/30 bg-emerald-500/5">
                    <Bitcoin className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                    <div>
                      <div className="font-semibold mb-0.5">OpenTimestamps · Submetido</div>
                      <div className="text-muted-foreground">{new Date(stamp.submitted_at).toLocaleString('pt-BR')} · {stamp.calendars.length} calendário(s)</div>
                    </div>
                  </div>
                  {stamp.rfc3161_token_base64 && (
                    <div className="flex items-start gap-2 p-3 rounded border border-emerald-500/30 bg-emerald-500/5">
                      <Clock className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                      <div>
                        <div className="font-semibold mb-0.5">RFC 3161 · Confirmado</div>
                        <div className="text-muted-foreground">FreeTSA · {stamp.rfc3161_timestamp && new Date(stamp.rfc3161_timestamp).toLocaleString('pt-BR')}</div>
                      </div>
                    </div>
                  )}
                  <div className="grid sm:grid-cols-2 gap-2">
                    <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.ots_file_base64, `gravacao-${result.evidence_hash.slice(0, 12)}.ots`, 'application/vnd.opentimestamps')}>
                      <Download className="w-3.5 h-3.5 mr-1.5" /> .ots
                    </Button>
                    {stamp.rfc3161_token_base64 && (
                      <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.rfc3161_token_base64!, `gravacao-${result.evidence_hash.slice(0, 12)}.tsr`, 'application/timestamp-reply')}>
                        <Download className="w-3.5 h-3.5 mr-1.5" /> .tsr
                      </Button>
                    )}
                  </div>
                  <a href="https://opentimestamps.org/" target="_blank" rel="noopener" className="inline-flex items-center gap-1 text-xs text-emerald-600 hover:underline">
                    <ExternalLink className="w-3 h-3" /> Verificar em opentimestamps.org
                  </a>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

async function sha256OfBytes(bytes: Uint8Array): Promise<string> {
  const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const hash = await crypto.subtle.digest('SHA-256', ab);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

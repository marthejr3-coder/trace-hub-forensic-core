import { useRef, useState } from 'react';
import { StjComplianceBanner } from '@/components/juridico/StjComplianceBanner';
import { useCredits } from '@/components/credits/CreditsGateProvider';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Crop, Loader2, Hash, Download, Camera, Bitcoin, Clock, ExternalLink, FileText, Image as ImageIcon, Globe, Package } from 'lucide-react';
import { toast } from 'sonner';
import { isIOS, openPopupForDownload, downloadBlob } from '@/lib/ios-download';
import IOSLimitationNotice from '@/components/IOSLimitationNotice';
import AssinaturaDigital from '@/components/juridico/AssinaturaDigital';

function supportsScreenCapture(): boolean {
  return typeof navigator !== 'undefined'
    && !!navigator.mediaDevices
    && typeof navigator.mediaDevices.getDisplayMedia === 'function';
}
import { supabase } from '@/integrations/supabase/client';
import { generateSHA256 } from '@/lib/forensic-hash';
import { registerForensicReport } from '@/lib/forensic-seal';
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

interface SelectiveResult {
  image_data_url: string;
  image_hash: string;
  width: number;
  height: number;
  region: { x: number; y: number; w: number; h: number };
  source_label: string;
  captured_at: string;
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

export default function CapturaSeletiva() {
  const { author } = useForensicAuthor();
  const { consume: __consumeCredit } = useCredits();
  const [capturing, setCapturing] = useState(false);
  const [snapshot, setSnapshot] = useState<{ url: string; w: number; h: number } | null>(null);
  const [result, setResult] = useState<SelectiveResult | null>(null);
  const [stamp, setStamp] = useState<StampResult | null>(null);
  const [stamping, setStamping] = useState(false);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [packaging, setPackaging] = useState(false);

  const overlayRef = useRef<HTMLDivElement>(null);
  const imgRef = useRef<HTMLImageElement>(null);
  const reportRef = useRef<HTMLDivElement>(null);
  const dragStart = useRef<{ x: number; y: number } | null>(null);
  const [selection, setSelection] = useState<{ x: number; y: number; w: number; h: number } | null>(null);

  const { generating, exportPDF, exportPNG } = useForensicExport(
    // @ts-ignore migration: strict-mode wave
    reportRef,
    'recorte-cartorial',
    () => result?.evidence_hash?.slice(0, 16),
    setPdfBase64,
  );

  const startCapture = async () => {
    if (!supportsScreenCapture()) {
      toast.error('Seu navegador não suporta captura de tela. Use a gravação nativa do iOS.');
      return;
    }
    setCapturing(true);
    setSnapshot(null);
    setResult(null);
    setStamp(null);
    setSelection(null);
    try {
      // @ts-ignore
      const stream: MediaStream = await navigator.mediaDevices.getDisplayMedia({
        video: { frameRate: 30 },
        audio: false,
      });
      const track = stream.getVideoTracks()[0];
      const settings = track.getSettings();
      const w = settings.width || 1280;
      const h = settings.height || 720;

      const video = document.createElement('video');
      video.srcObject = stream;
      video.muted = true;
      await video.play();
      await new Promise((r) => setTimeout(r, 600));

      const canvas = document.createElement('canvas');
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext('2d');
      if (!ctx) throw new Error('Canvas 2D indisponível');
      ctx.drawImage(video, 0, 0, w, h);

      stream.getTracks().forEach((t) => t.stop());
      video.srcObject = null;

      const dataUrl = canvas.toDataURL('image/png');
      setSnapshot({ url: dataUrl, w, h });
      toast.success('Tela capturada — arraste para selecionar a área');
    } catch (e: any) {
      if (e?.name === 'NotAllowedError') toast.error('Permissão de captura negada');
      else toast.error(e?.message || 'Falha ao capturar tela');
    } finally {
      setCapturing(false);
    }
  };

  const onPointerDown = (e: React.PointerEvent) => {
    if (!overlayRef.current) return;
    try { overlayRef.current.setPointerCapture(e.pointerId); } catch {}
    const rect = overlayRef.current.getBoundingClientRect();
    dragStart.current = { x: e.clientX - rect.left, y: e.clientY - rect.top };
    setSelection({ x: dragStart.current.x, y: dragStart.current.y, w: 0, h: 0 });
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!dragStart.current || !overlayRef.current) return;
    const rect = overlayRef.current.getBoundingClientRect();
    const cx = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
    const cy = Math.max(0, Math.min(e.clientY - rect.top, rect.height));
    setSelection({
      x: Math.min(dragStart.current.x, cx),
      y: Math.min(dragStart.current.y, cy),
      w: Math.abs(cx - dragStart.current.x),
      h: Math.abs(cy - dragStart.current.y),
    });
  };
  const onPointerUp = () => { dragStart.current = null; };

  const confirmCrop = async () => {
    if (!snapshot || !selection || !imgRef.current || selection.w < 10 || selection.h < 10) {
      toast.error('Selecione uma área maior arrastando');
      return;
    }
    try {
      const displayed = imgRef.current.getBoundingClientRect();
      const scaleX = snapshot.w / displayed.width;
      const scaleY = snapshot.h / displayed.height;
      const realX = Math.round(selection.x * scaleX);
      const realY = Math.round(selection.y * scaleY);
      const realW = Math.round(selection.w * scaleX);
      const realH = Math.round(selection.h * scaleY);

      const img = new Image();
      img.src = snapshot.url;
      await new Promise((r, rej) => { img.onload = () => r(null); img.onerror = rej; });
      const canvas = document.createElement('canvas');
      canvas.width = realW;
      canvas.height = realH;
      const ctx = canvas.getContext('2d');
      if (!ctx) throw new Error('Canvas indisponível');
      ctx.drawImage(img, realX, realY, realW, realH, 0, 0, realW, realH);
      const cropDataUrl = canvas.toDataURL('image/png');

      const blob = await (await fetch(cropDataUrl)).blob();
      const buf = new Uint8Array(await blob.arrayBuffer());
      const imageHash = await sha256OfBytes(buf);

      let capturedAt = new Date().toISOString();
      let timestampSource = 'local server (fallback)';
      try {
        const r = await fetch('https://worldtimeapi.org/api/timezone/Etc/UTC');
        const j = await r.json();
        capturedAt = j.utc_datetime || capturedAt;
        timestampSource = 'worldtimeapi.org (UTC)';
      } catch {}

      const evidencePayload = JSON.stringify({
        image_hash: imageHash,
        region: { x: realX, y: realY, w: realW, h: realH },
        full_size: { w: snapshot.w, h: snapshot.h },
        captured_at: capturedAt,
        timestamp_source: timestampSource,
        source: window.location.href,
      });
      const evidenceHash = await generateSHA256(evidencePayload);

      setResult({
        image_data_url: cropDataUrl,
        image_hash: imageHash,
        width: realW,
        height: realH,
        region: { x: realX, y: realY, w: realW, h: realH },
        source_label: 'Tela compartilhada pelo operador',
        captured_at: capturedAt,
        timestamp_source: timestampSource,
        evidence_hash: evidenceHash,
      });
      registerForensicReport({
        evidenceHash,
        reportType: 'selective_capture',
        subject: `Recorte ${realW}×${realH}px @ ${new Date(capturedAt).toLocaleString('pt-BR')}`,
        metadata: { image_hash: imageHash, region: { x: realX, y: realY, w: realW, h: realH }, timestamp_source: timestampSource },
      });
      toast.success('Recorte selado com SHA-256');
    } catch (e: any) {
      toast.error(e?.message || 'Falha ao processar recorte');
    }
  };

  const handleStamp = async () => {
    if (!result?.evidence_hash) return;
    setStamping(true);
    try {
      const __gate = await __consumeCredit('juridico-captura');
      if (!__gate.allowed) return;
      const { data, error } = await supabase.functions.invoke('notarial-stamp', { body: { evidence_hash: result.evidence_hash } });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setStamp({
        ots_file_base64: data.opentimestamps.ots_file_base64,
        rfc3161_token_base64: data.rfc3161?.token_base64 ?? null,
        rfc3161_timestamp: data.rfc3161?.timestamp ?? null,
        calendars: data.opentimestamps.calendars_succeeded ?? [],
        submitted_at: data.submitted_at,
      });
      toast.success('Recorte ancorado em blockchain');
    } catch (e: any) {
      toast.error(e?.message || 'Falha ao selar');
    } finally {
      setStamping(false);
    }
  };

  const imageFileName = result
    ? `recorte-${result.evidence_hash.slice(0, 12)}.png`
    : '';

  const downloadImage = () => {
    if (!result) return;
    const a = document.createElement('a');
    a.href = result.image_data_url;
    a.download = imageFileName;
    a.click();
  };

  const downloadBase64 = (b64: string, filename: string, mime: string) => {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPackage = async () => {
    if (!result || !reportRef.current) return;
    const popup = openPopupForDownload('Montando pacote da prova…');
    setPackaging(true);
    const t = toast.loading('Montando pacote completo da prova…');
    try {
      const { sectionedPDFToBase64 } = await import('@/lib/pdf-section-export');
      const pdfBase64Str = await sectionedPDFToBase64(reportRef.current, {
        shortHash: result.evidence_hash.slice(0, 16),
      });
      setPdfBase64(pdfBase64Str);
      const imgBlob = await (await fetch(result.image_data_url)).blob();
      const { buildNotarialEvidenceZip } = await import('@/lib/notarial-evidence-zip');
      const { blob, filename } = await buildNotarialEvidenceZip({
        prefix: 'recorte-notarial',
        label: 'Recorte Notarial Digital',
        evidenceHash: result.evidence_hash,
        pdfBase64: pdfBase64Str,
        pdfFilename: 'relatorio_evidencia_recorte.pdf',
        otsBase64: stamp?.ots_file_base64 ?? null,
        tsrBase64: stamp?.rfc3161_token_base64 ?? null,
        media: [{ filename: imageFileName, blob: imgBlob, description: 'Recorte capturado da tela (PNG original)' }],
        meta: {
          'Fonte': result.source_label,
          'Capturado em': result.captured_at,
          'Dimensões do recorte': `${result.region.w}x${result.region.h}px`,
          'Hash da imagem (SHA-256)': result.image_hash,
        },
        operatorName: author?.fullName || null,
        startedAt: result.captured_at,
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



  return (
    <div className="space-y-4">
      <StjComplianceBanner variant="collection" />
      <div className="rounded-lg border bg-muted/30 p-3 text-xs space-y-1">
        <p><strong>Como usar:</strong> 1) Abra o site na tela. 2) "Capturar tela". 3) Arraste para selecionar a área. 4) Confirme. 5) Sele em blockchain.</p>
      </div>

      {!snapshot && (
        <>
          {!supportsScreenCapture() ? (
            <IOSLimitationNotice
              feature="Recorte de tela"
              icon={Crop}
              description="O Safari do iOS não permite que sites capturem a tela para recorte. Como alternativa, faça um screenshot nativo no iPhone e use as ferramentas de upload abaixo — todas com a mesma validade jurídica."
              alternatives={[
                {
                  icon: Camera,
                  title: 'Screenshot nativo do iPhone',
                  description: 'Pressione Botão Lateral + Aumentar Volume simultaneamente. A imagem é salva em Fotos com metadados originais. Use o Decoder de Metadados ou o WhatsApp Validator para gerar hash SHA-256 e laudo do print.',
                },
                {
                  icon: Globe,
                  title: 'Modo URL pública',
                  description: 'Se a prova é uma página web, troque para a aba "URL pública" da Ata Notarial — funciona no iPhone e captura a página inteira do servidor.',
                },
                {
                  icon: ImageIcon,
                  title: 'Anexar imagem ao caso',
                  description: 'Crie um caso no Dashboard e anexe o screenshot direto — o sistema gera hash SHA-256 e cadeia de custódia completa.',
                },
              ]}
              tutorialUrl="https://support.apple.com/pt-br/HT200289"
              footnote="Screenshots nativos do iOS preservam metadados EXIF e são plenamente aceitos como prova quando acompanhados de hash SHA-256."
            />
          ) : (
            <Button onClick={startCapture} disabled={capturing} className="w-full">
              {capturing ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Camera className="w-4 h-4 mr-2" />}
              Capturar tela / aba específica
            </Button>
          )}
        </>
      )}

      {snapshot && !result && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Crop className="w-4 h-4 text-primary" /> Arraste para selecionar a área
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div
              ref={overlayRef}
              className="relative inline-block max-w-full overflow-hidden border rounded select-none touch-none cursor-crosshair"
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
            >
              <img ref={imgRef} src={snapshot.url} alt="Snapshot da página capturada" className="max-w-full block pointer-events-none select-none" draggable={false} />
              {selection && (
                <div
                  className="absolute border-2 border-primary bg-primary/15 pointer-events-none"
                  style={{ left: selection.x, top: selection.y, width: selection.w, height: selection.h }}
                />
              )}
            </div>
            <div className="flex gap-2">
              <Button onClick={confirmCrop} disabled={!selection || selection.w < 10 || selection.h < 10}>
                <Hash className="w-4 h-4 mr-2" /> Confirmar e gerar hash
              </Button>
              <Button variant="outline" onClick={startCapture}>Recapturar</Button>
            </div>
          </CardContent>
        </Card>
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
              Um único arquivo com o relatório em PDF, o recorte .png, os selos .ots/.tsr já emitidos
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
                <Button variant="outline" size="sm" onClick={downloadImage}>
                  <Download className="w-4 h-4 mr-2" /> Recorte (.png)
                </Button>
                {stamp && (
                  <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.ots_file_base64, `recorte-${result.evidence_hash.slice(0, 12)}.ots`, 'application/vnd.opentimestamps')}>
                    <Download className="w-3.5 h-3.5 mr-1.5" /> .ots
                  </Button>
                )}
                {stamp?.rfc3161_token_base64 && (
                  <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.rfc3161_token_base64!, `recorte-${result.evidence_hash.slice(0, 12)}.tsr`, 'application/timestamp-reply')}>
                    <Download className="w-3.5 h-3.5 mr-1.5" /> .tsr
                  </Button>
                )}
                <Button variant="ghost" size="sm" onClick={() => setResult(null)}>Refazer</Button>
              </div>
            </details>
          </div>


          <ReportRoot ref={reportRef}>
            <ReportFrontispiece
              titleLines={['Recorte', 'Notarial Digital']}
              tagline="Captura seletiva forense · Prova autosuficiente"
              certificationText={
                <>
                  <strong>Certifica-se</strong>, para os devidos fins de direito, que em{' '}
                  <strong>{new Date(result.captured_at).toLocaleString('pt-BR')}</strong>{' '}
                  (timestamp <em>{result.timestamp_source}</em>) foi realizada captura forense
                  seletiva da tela compartilhada pelo operador, com extração precisa de área
                  retangular medindo <strong>{result.width} × {result.height} pixels</strong>. A
                  integridade do material foi assegurada mediante geração de impressão digital
                  criptográfica SHA-256.
                </>
              }
              summaryRows={[
                { label: 'Nome do arquivo', value: imageFileName },
                { label: 'Origem', value: result.source_label },
                { label: 'Dimensões do recorte', value: `${result.width} × ${result.height} px` },
                { label: 'Coordenadas', value: `x=${result.region.x}, y=${result.region.y}` },
                { label: 'Capturado em', value: new Date(result.captured_at).toLocaleString('pt-BR') },
                { label: 'Fonte de tempo', value: result.timestamp_source },
              ]}
              evidenceHash={result.evidence_hash}
            />

            <PartSection className="pt-8">
              <PartHeader number="I" title="Da Captura Visual" subtitle="Imagem fiel da área selecionada no instante da captura" />
            </PartSection>

            <PartSection breakBefore={false} tall className="mt-5">
              <div className="px-3 py-1.5 mb-2" style={{ backgroundColor: '#f1f5f9', border: '1px solid #cbd5e1' }}>
                <span className="text-[9px] uppercase font-bold" style={{ fontFamily: "'Cinzel', Georgia, serif", color: '#5a5a5a', letterSpacing: '0.28em' }}>
                  Anexo Único — Recorte Capturado
                </span>
              </div>
              <figure className="border-2 p-2 bg-white shadow-md" style={{ borderColor: '#1a1a1a' }}>
                <img src={result.image_data_url} alt="Recorte" className="w-full block" />
                <figcaption className="text-[9.5px] text-center pt-2 mt-2 border-t border-slate-200" style={{ fontFamily: FONT_BODY }}>
                  <strong>Imagem 1.</strong> Recorte fiel renderizado em{' '}
                  {new Date(result.captured_at).toLocaleString('pt-BR')}.
                  <span className="block text-[8.5px] mt-0.5" style={{ fontFamily: FONT_MONO, color: '#5a5a5a' }}>
                    SHA-256 da imagem: {result.image_hash}
                  </span>
                </figcaption>
              </figure>
            </PartSection>

            <PartSection className="pt-8">
              <PartHeader number="II" title="Dos Metadados Técnicos" subtitle="Coordenadas, dimensões e contexto de captura" />
            </PartSection>

            <PartSection breakBefore={false} className="mt-4">
              <SubHeader>2.1 · Geometria do recorte</SubHeader>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 mt-2">
                <ReportField label="Nome do arquivo de imagem" value={imageFileName} mono />
                <ReportField label="Largura" value={`${result.width} px`} mono />
                <ReportField label="Altura" value={`${result.height} px`} mono />
                <ReportField label="Posição X" value={String(result.region.x)} mono />
                <ReportField label="Posição Y" value={String(result.region.y)} mono />
                <ReportField label="Método" value="getDisplayMedia + Canvas crop" />
                <ReportField label="Origem URL" value={window.location.href} mono />
              </dl>
            </PartSection>

            <PartSection className="pt-8">
              <PartHeader number="III" title="Da Integridade Criptográfica" subtitle="Impressões digitais SHA-256 que garantem inalterabilidade do recorte" />
            </PartSection>

            <PartSection breakBefore={false} className="mt-4">
              <p className="text-[11.5px] leading-[1.65] text-justify mb-4" style={{ fontFamily: FONT_BODY }}>
                As funções <em>hash</em> SHA-256 abaixo constituem impressão digital única e
                irreversível do recorte capturado. Qualquer alteração — ainda que de um único pixel —
                resultaria em <em>hash</em> completamente distinto.
              </p>
              <div className="space-y-3">
                <div>
                  <SubHeader>3.1 · Hash binário da imagem PNG</SubHeader>
                  <p className="font-mono text-[10px] break-all bg-slate-50 border border-slate-300 px-3 py-2 rounded" style={{ fontFamily: FONT_MONO }}>
                    {result.image_hash}
                  </p>
                </div>
                <HashHighlight
                  label="3.2 · Código Único de Verificação · SHA-256"
                  description="Hash composto que sintetiza imagem + região + timestamp. Use para validação pública."
                  hash={result.evidence_hash}
                />
              </div>
            </PartSection>

            <ValidationPage hash={result.evidence_hash} reportType="selective_capture" />

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
                    <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.ots_file_base64, `recorte-${result.evidence_hash.slice(0, 12)}.ots`, 'application/vnd.opentimestamps')}>
                      <Download className="w-3.5 h-3.5 mr-1.5" /> .ots
                    </Button>
                    {stamp.rfc3161_token_base64 && (
                      <Button size="sm" variant="outline" onClick={() => downloadBase64(stamp.rfc3161_token_base64!, `recorte-${result.evidence_hash.slice(0, 12)}.tsr`, 'application/timestamp-reply')}>
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

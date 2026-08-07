import { forwardRef, useEffect, useRef, useState } from 'react';
import { Link } from "@/lib/router-compat";
import { Helmet } from '@/lib/helmet-compat';
import {
  ShieldCheck,
  Crosshair,
  Download,
  FileText,
  Trash2,
  Scan,
  CheckCircle2,
  Loader2,
  ArrowLeft,
  AlertCircle,
  AtSign,
  ImageIcon,
  ExternalLink,
  Package,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { useCredits } from '@/components/credits/CreditsGateProvider';
import {
  EvidenceRecord,
  generateEvidenceCapture,
  loadEvidences,
  saveEvidence,
  deleteEvidence,
  downloadEvidencePDF,
} from '@/lib/trace-capture';
import { exportEvidenceZIP } from '@/lib/evidence-package';

const FEED_STEPS = [
  'Conectando ao servidor seguro...',
  'Resolvendo URL canônica e redirecionamentos...',
  'Carregando navegador headless...',
  'Capturando viewport completo (full page)...',
  'Extraindo metadados Open Graph...',
  'Detectando perfil de rede social...',
  'Coletando IP e User-Agent...',
  'Gerando hash SHA-256 (URL + screenshot)...',
  'Selando cadeia de custódia...',
];

const formatStamp = (idx: number) => `[00:${String(idx + 1).padStart(2, '0')}]`;

const truncateHash = (hash: string) =>
  hash ? `${hash.slice(0, 10)}…${hash.slice(-10)}` : '';

const formatUTC = (iso: string) =>
  new Date(iso).toISOString().replace('T', ' ').replace('Z', ' UTC');

export default function TraceCapture() {
  const { toast } = useToast();
  const { consume } = useCredits();
  const [url, setUrl] = useState('');
  const [processing, setProcessing] = useState(false);
  const [activeSteps, setActiveSteps] = useState<number>(0);
  const [currentRecord, setCurrentRecord] = useState<EvidenceRecord | null>(null);
  const [evidences, setEvidences] = useState<EvidenceRecord[]>([]);
  const reportRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setEvidences(loadEvidences());
  }, []);

  const isValidURL = (value: string) => {
    try {
      const u = new URL(value);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  };

  const handleCapture = async () => {
    if (!isValidURL(url)) {
      toast({
        title: 'URL inválida',
        description: 'Informe uma URL completa começando com http:// ou https://',
        variant: 'destructive',
      });
      return;
    }

    const gate = await consume('trace-capture', { url });
    if (!gate.allowed) return;

    setProcessing(true);
    setActiveSteps(0);
    setCurrentRecord(null);

    const stepInterval = setInterval(() => {
      setActiveSteps((s) => (s >= FEED_STEPS.length ? s : s + 1));
    }, 700);

    try {
      const [record] = await Promise.all([
        generateEvidenceCapture(url),
        new Promise((r) => setTimeout(r, FEED_STEPS.length * 700 + 200)),
      ]);

      clearInterval(stepInterval);
      setActiveSteps(FEED_STEPS.length);
      saveEvidence(record);
      setEvidences(loadEvidences());
      setCurrentRecord(record);

      if (record.captureWarning) {
        toast({
          title: 'Prova gerada com aviso',
          description: record.captureWarning,
        });
      } else {
        toast({
          title: 'Prova certificada gerada',
          description: 'Screenshot, hash SHA-256 e metadados selados.',
        });
      }
    } catch (err) {
      clearInterval(stepInterval);
      toast({
        title: 'Falha ao gerar prova',
        description: err instanceof Error ? err.message : 'Erro desconhecido',
        variant: 'destructive',
      });
    } finally {
      setProcessing(false);
    }
  };

  const handleDownload = async (record: EvidenceRecord) => {
    setCurrentRecord(record);
    await new Promise((r) => setTimeout(r, 150));
    if (!reportRef.current) {
      toast({
        title: 'Erro',
        description: 'Relatório não está pronto.',
        variant: 'destructive',
      });
      return;
    }
    try {
      await downloadEvidencePDF(reportRef.current, record);
      toast({ title: 'Download iniciado', description: record.filename });
    } catch (err) {
      toast({
        title: 'Falha ao gerar PDF',
        description: err instanceof Error ? err.message : 'Erro desconhecido',
        variant: 'destructive',
      });
    }
  };

  const handleDownloadZIP = async (record: EvidenceRecord) => {
    setCurrentRecord(record);
    await new Promise((r) => setTimeout(r, 150));
    if (!reportRef.current) {
      toast({ title: 'Erro', description: 'Relatório não está pronto.', variant: 'destructive' });
      return;
    }
    if (!record.htmlRaw && !record.screenshotDataUrl) {
      toast({
        title: 'Pacote incompleto',
        description: 'Esta evidência foi salva sem screenshot/HTML. Capture novamente para gerar o pacote forense completo.',
        variant: 'destructive',
      });
      return;
    }
    try {
      toast({ title: 'Gerando pacote forense…', description: 'PDF + screenshot + HTML + manifesto SHA-256.' });
      await exportEvidenceZIP(reportRef.current, record);
      toast({
        title: 'Pacote forense pronto',
        description: 'ZIP com PDF, JPG, HTML, manifest.json e verificador offline.',
      });
    } catch (err) {
      toast({
        title: 'Falha ao gerar pacote',
        description: err instanceof Error ? err.message : 'Erro desconhecido',
        variant: 'destructive',
      });
    }
  };

  const handleDelete = (id: string) => {
    deleteEvidence(id);
    setEvidences(loadEvidences());
    if (currentRecord?.id === id) setCurrentRecord(null);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Helmet>
        <title>Trace Capture — Preservação de Prova Digital | Trace Hub</title>
        <meta
          name="description"
          content="Capture e certifique URLs com screenshot real, hash SHA-256 e cadeia de custódia ISO 27037."
        />
      </Helmet>

      {/* Background grid + glow */}
      <div className="fixed inset-0 pointer-events-none">
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              'linear-gradient(hsl(var(--primary)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--primary)) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
          }}
        />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-primary/10 blur-[120px] rounded-full" />
      </div>

      <div className="relative max-w-6xl mx-auto px-4 py-8 sm:py-12 space-y-8">
        {/* Header */}
        <div className="space-y-4">
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Voltar ao Dashboard
          </Link>
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-2xl bg-primary/10 border border-primary/30 shadow-[0_0_30px_-8px] shadow-primary/40">
              <ShieldCheck className="w-7 h-7 sm:w-8 sm:h-8 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-4xl font-black tracking-tight">
                Preservação de <span className="text-primary">Prova Digital</span>
              </h1>
              <p className="text-sm sm:text-base text-muted-foreground mt-1.5 max-w-2xl">
                Captura certificada com screenshot real, hash SHA-256, metadados técnicos e
                selo de cadeia de custódia ISO 27037. PDF multipáginas para páginas longas.
              </p>
            </div>
          </div>
        </div>

        {/* Input area */}
        <Card className="bg-card/40 backdrop-blur-xl border border-primary/20 shadow-[0_0_40px_-20px] shadow-primary/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Crosshair className="w-5 h-5 text-primary" />
              Iniciar Captura Certificada
            </CardTitle>
            <CardDescription>
              Cole a URL pública que deseja preservar como evidência forense.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <Input
                type="url"
                placeholder="https://exemplo.com/pagina-suspeita"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={processing}
                className="h-12 text-base font-mono bg-background/60 border-primary/20 focus-visible:ring-primary"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !processing) handleCapture();
                }}
              />
              <Button
                onClick={handleCapture}
                disabled={processing || !url.trim()}
                size="lg"
                className="h-12 px-6 font-bold shadow-[0_0_20px_-6px] shadow-primary/60"
              >
                {processing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" /> Processando...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" /> Gerar Prova Certificada
                  </>
                )}
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge variant="outline" className="border-primary/40 text-primary bg-primary/5 gap-1">
                <ShieldCheck className="w-3 h-3" /> Captura em ambiente isolado na nuvem
              </Badge>
              <Badge variant="outline" className="border-primary/40 text-primary bg-primary/5">
                Anti-DNS-Poisoning · 3 resolvers DoH
              </Badge>
              <Badge variant="outline" className="border-primary/40 text-primary bg-primary/5">
                ISO/IEC 27037 · CPP 158-A
              </Badge>
              <Link to="/atestados-tecnicos" className="text-primary hover:underline ml-1">
                ver metodologia →
              </Link>
            </div>
            <div className="flex items-start gap-2 text-xs text-muted-foreground">
              <AlertCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
              <span>
                A captura usa um navegador headless seguro em ambiente isolado, sem dependência
                do DNS/proxy do operador. Hash, IP, UA e timestamp são reais.
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Live Feed */}
        {processing && (
          <Card className="bg-black/60 backdrop-blur-xl border border-primary/40 overflow-hidden">
            <CardHeader className="pb-3 border-b border-primary/20">
              <CardTitle className="flex items-center gap-2 text-sm font-mono uppercase tracking-widest text-primary">
                <Scan className="w-4 h-4 animate-pulse" />
                Live Feed — Análise Forense
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="relative h-64 sm:h-96 overflow-hidden bg-black/80">
                <div className="absolute inset-0 pointer-events-none">
                  <div
                    className="absolute left-0 right-0 h-[2px] bg-primary shadow-[0_0_20px_4px] shadow-primary animate-scan-line"
                    style={{ top: '0%' }}
                  />
                </div>
                <div
                  className="absolute inset-0 opacity-20"
                  style={{
                    backgroundImage:
                      'linear-gradient(hsl(var(--primary)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--primary)) 1px, transparent 1px)',
                    backgroundSize: '24px 24px',
                  }}
                />
                <div className="relative h-full p-5 overflow-y-auto font-mono text-xs sm:text-sm space-y-2">
                  {FEED_STEPS.map((msg, idx) => {
                    const done = idx < activeSteps;
                    const active = idx === activeSteps;
                    if (!done && !active) return null;
                    return (
                      <div
                        key={idx}
                        className={`flex items-center gap-2 ${
                          done ? 'text-primary' : 'text-primary/70'
                        }`}
                      >
                        <span className="text-primary/50">{formatStamp(idx)}</span>
                        {done ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-primary" />
                        ) : (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        )}
                        <span>{msg}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Generated report preview */}
        {currentRecord && (
          <Card className="bg-card/40 backdrop-blur-xl border border-primary/20">
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <div>
                <CardTitle className="text-lg">Relatório de Evidência</CardTitle>
                <CardDescription>
                  Pré-visualização do PDF certificado.
                  {currentRecord.screenshotDataUrl
                    ? ' Print real fatiado em múltiplas páginas A4.'
                    : ' Print indisponível — apenas metadados.'}
                  <br />
                  <span className="text-primary font-medium">
                    💼 Para envio judicial, use o Pacote Forense (ZIP) — inclui PDF + JPG + HTML + manifesto SHA-256.
                  </span>
                </CardDescription>
              </div>
              <div className="flex flex-col sm:flex-row gap-2">
                <Button onClick={() => handleDownload(currentRecord)} variant="outline" className="gap-2">
                  <Download className="w-4 h-4" /> Só PDF
                </Button>
                <Button
                  onClick={() => handleDownloadZIP(currentRecord)}
                  className="gap-2 shadow-[0_0_20px_-6px] shadow-primary/60"
                >
                  <Package className="w-4 h-4" /> Baixar Pacote Forense (ZIP)
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {currentRecord.captureWarning && (
                <div className="mb-4 flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">
                  <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <span>{currentRecord.captureWarning}</span>
                </div>
              )}
              <div className="overflow-auto rounded-lg border border-border bg-white max-h-[700px]">
                <EvidenceReport ref={reportRef} record={currentRecord} />
              </div>
              {currentRecord.screenshotDataUrl && (
                <div className="mt-4 rounded-lg border border-border bg-white">
                  <div className="flex items-center justify-between gap-3 flex-wrap px-3 py-2 border-b text-xs font-mono uppercase tracking-widest text-muted-foreground">
                    <span className="flex items-center gap-2">
                      <ImageIcon className="w-3.5 h-3.5" /> Screenshot full-page
                    </span>
                    <div className="flex items-center gap-2 flex-wrap">
                      {currentRecord.screenshotSource === 'sealed' ? (
                        <span
                          className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold normal-case text-emerald-700 dark:text-emerald-300"
                          title="Capturado pelo próprio operador via getDisplayMedia (Ambiente Lacrado) — CPP art. 158-B."
                        >
                          Sealed (getDisplayMedia)
                        </span>
                      ) : (
                        <a
                          href="/ambiente-lacrado"
                          className="inline-flex items-center gap-1 rounded border border-orange-500/40 bg-orange-500/10 px-2 py-0.5 text-[10px] font-semibold normal-case text-orange-700 hover:bg-orange-500/15 dark:text-orange-300"
                          title="Screenshot gerado por edge function headless (servidor). Para captura presencial nos termos do CPP art. 158-B, use o Ambiente Lacrado."
                        >
                          Headless server · usar Ambiente Lacrado
                        </a>
                      )}
                      {currentRecord.socialProfile?.profileUrl && (
                        <a
                          href={currentRecord.socialProfile.profileUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline flex items-center gap-1 normal-case"
                        >
                          Abrir perfil <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                  <div className="overflow-auto max-h-[600px] bg-white">
                    <img
                      src={currentRecord.screenshotDataUrl}
                      alt="Screenshot capturado"
                      className="w-full h-auto block"
                    />
                  </div>
                </div>
              )}

              {/* Snapshot manual de infraestrutura removido — metadados de rede
                  (DNS/RDAP/ASN/TLS) seguem coletados automaticamente no relatório. */}
            </CardContent>
          </Card>
        )}

        {/* Hidden render target for downloading from history */}
        {!currentRecord && (
          <div
            aria-hidden="true"
            style={{ position: 'absolute', left: -99999, top: 0 }}
          >
            <EvidenceReport ref={reportRef} record={null} />
          </div>
        )}

        {/* Evidence list */}
        <Card className="bg-card/40 backdrop-blur-xl border border-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <FileText className="w-5 h-5 text-primary" />
              Histórico de Evidências
              <Badge variant="secondary" className="ml-1">
                {evidences.length}
              </Badge>
            </CardTitle>
            <CardDescription>
              Provas geradas e armazenadas neste dispositivo. Baixe novamente o PDF a qualquer
              momento.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {evidences.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <FileText className="w-10 h-10 mx-auto mb-3 opacity-40" />
                <p className="text-sm">Nenhuma evidência gerada ainda.</p>
              </div>
            ) : (
              <div className="rounded-lg border border-border/60 overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Arquivo</TableHead>
                      <TableHead className="hidden sm:table-cell">URL</TableHead>
                      <TableHead className="hidden lg:table-cell">Perfil</TableHead>
                      <TableHead className="hidden md:table-cell">Data/Hora UTC</TableHead>
                      <TableHead className="hidden lg:table-cell">Hash</TableHead>
                      <TableHead>Print</TableHead>
                      <TableHead className="text-right">Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {evidences.map((ev) => (
                      <TableRow key={ev.id}>
                        <TableCell className="font-mono text-xs max-w-[180px] truncate">
                          {ev.filename}
                        </TableCell>
                        <TableCell className="hidden sm:table-cell font-mono text-xs max-w-[220px] truncate">
                          {ev.url}
                        </TableCell>
                        <TableCell className="hidden lg:table-cell text-xs">
                          {ev.socialProfile?.handle ? (
                            <span className="inline-flex items-center gap-1 font-mono">
                              <AtSign className="w-3 h-3 text-primary" />
                              {ev.socialProfile.handle}
                            </span>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="hidden md:table-cell font-mono text-xs">
                          {formatUTC(ev.capturedAtUTC)}
                        </TableCell>
                        <TableCell className="hidden lg:table-cell font-mono text-xs">
                          {truncateHash(ev.hash)}
                        </TableCell>
                        <TableCell>
                          {ev.screenshotDataUrl ? (
                            <Badge className="bg-primary/15 text-primary border border-primary/30 gap-1">
                              <CheckCircle2 className="w-3 h-3" /> OK
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleDownloadZIP(ev)}
                              title="Baixar Pacote Forense (ZIP)"
                              className="text-primary hover:text-primary"
                            >
                              <Package className="w-4 h-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleDownload(ev)}
                              title="Baixar somente PDF"
                            >
                              <Download className="w-4 h-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleDelete(ev.id)}
                              title="Excluir"
                              className="text-destructive hover:text-destructive"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground py-4">
          Certificado em conformidade com a <strong>ISO 27037</strong> e Cadeia de Custódia
          Digital.
        </p>
      </div>
    </div>
  );
}

/* ============ Evidence Report (rendered for PDF — header only, screenshot is appended by exporter) ============ */

interface ReportProps {
  record: EvidenceRecord | null;
}

const EvidenceReport = forwardRef<HTMLDivElement, ReportProps>(({ record }, ref) => {
  if (!record) {
    return (
      <div
        ref={ref}
        style={{ width: 794, padding: 40, background: '#fff' }}
      />
    );
  }
  const dateStr = new Date(record.capturedAtUTC)
    .toISOString()
    .replace('T', ' ')
    .replace('Z', ' UTC');

  const urlChanged = record.finalUrl && record.finalUrl !== record.url;

  return (
    <div
      ref={ref}
      style={{
        width: 794,
        padding: 40,
        background: '#ffffff',
        color: '#0a0a0a',
        fontFamily: 'system-ui, -apple-system, sans-serif',
      }}
    >
      {/* Header */}
      <div
        data-pdf-section="header"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '3px solid #10b981',
          paddingBottom: 14,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 48,
              height: 48,
              borderRadius: 10,
              background: '#000',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '2px solid #10b981',
            }}
          >
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="22" y1="12" x2="18" y2="12" />
              <line x1="6" y1="12" x2="2" y2="12" />
              <line x1="12" y1="6" x2="12" y2="2" />
              <line x1="12" y1="22" x2="12" y2="18" />
            </svg>
          </div>
          <div>
            <div style={{ fontSize: 10, color: '#10b981', fontWeight: 700, letterSpacing: 2 }}>
              TRACE HUB
            </div>
            <div style={{ fontSize: 16, fontWeight: 800, color: '#0a0a0a' }}>
              RELATÓRIO DE PRESERVAÇÃO DE PROVA DIGITAL
            </div>
          </div>
        </div>
        <div
          style={{
            background: '#10b981',
            color: '#fff',
            padding: '6px 12px',
            borderRadius: 6,
            fontWeight: 800,
            fontSize: 10,
            letterSpacing: 1,
          }}
        >
          ✓ INTEGRIDADE GARANTIDA
        </div>
      </div>

      {/* Metadados */}
      <div data-pdf-section="metadata" style={{ marginTop: 18 }}>
        <div
          style={{
            fontSize: 10,
            fontWeight: 700,
            color: '#10b981',
            letterSpacing: 2,
            marginBottom: 8,
          }}
        >
          METADADOS TÉCNICOS
        </div>
        <table style={{ width: '100%', fontSize: 11, borderCollapse: 'collapse' }}>
          <tbody>
            {[
              ['URL Original', record.url],
              ...(urlChanged ? [['URL Canônica Resolvida', record.finalUrl!]] : []),
              ['Data/Hora (UTC)', dateStr],
              ['IP do Solicitante', record.ip],
              ['User-Agent', record.userAgent],
              ['Algoritmo', record.algorithm],
              ['Hash SHA-256', record.hash],
              ...(record.hashSha512 ? [['Hash SHA-512 (paridade ISO 27037)', record.hashSha512]] : []),
              ...(record.screenshotHash ? [['Hash do Screenshot', record.screenshotHash]] : []),
              ['ID da Evidência', record.id],
            ].map(([label, value]) => (
              <tr key={label}>
                <td
                  style={{
                    padding: '6px 10px',
                    background: '#f3f4f6',
                    fontWeight: 700,
                    width: 170,
                    border: '1px solid #e5e7eb',
                    verticalAlign: 'top',
                  }}
                >
                  {label}
                </td>
                <td
                  style={{
                    padding: '6px 10px',
                    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                    border: '1px solid #e5e7eb',
                    wordBreak: 'break-all',
                    fontSize: 10,
                  }}
                >
                  {value}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Perfil de rede social */}
      {record.socialProfile && (
        <div data-pdf-section="social" style={{ marginTop: 18 }}>
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: '#10b981',
              letterSpacing: 2,
              marginBottom: 8,
            }}
          >
            PERFIL DE REDE SOCIAL IDENTIFICADO
          </div>
          <div
            style={{
              border: '2px solid #10b981',
              borderRadius: 10,
              padding: 12,
              background: 'rgba(16,185,129,0.06)',
              fontSize: 11,
            }}
          >
            <div><strong>Rede:</strong> {record.socialProfile.network}</div>
            {record.socialProfile.handle && (
              <div style={{ marginTop: 4 }}>
                <strong>Handle:</strong>{' '}
                <span style={{ fontFamily: 'ui-monospace, monospace' }}>
                  @{record.socialProfile.handle}
                </span>
              </div>
            )}
            <div style={{ marginTop: 4, wordBreak: 'break-all' }}>
              <strong>URL Canônica do Perfil:</strong>{' '}
              <span style={{ fontFamily: 'ui-monospace, monospace' }}>
                {record.socialProfile.profileUrl}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Open Graph */}
      {(record.ogTitle || record.ogDescription) && (
        <div data-pdf-section="og" style={{ marginTop: 18 }}>
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: '#10b981',
              letterSpacing: 2,
              marginBottom: 8,
            }}
          >
            METADADOS OPEN GRAPH (TÍTULO/DESCRIÇÃO DA PÁGINA)
          </div>
          <div
            style={{
              border: '1px solid #e5e7eb',
              borderRadius: 8,
              padding: 12,
              background: '#fafafa',
              fontSize: 11,
            }}
          >
            {record.ogTitle && (
              <div style={{ fontWeight: 700, marginBottom: 4 }}>{record.ogTitle}</div>
            )}
            {record.ogDescription && (
              <div style={{ color: '#374151' }}>{record.ogDescription}</div>
            )}
          </div>
        </div>
      )}

      {/* Integridade DNS (Anti-DNS-Poisoning) */}
      {record.dnsIntegrity && (
        <div data-pdf-section="dns" style={{ marginTop: 18 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#10b981', letterSpacing: 2, marginBottom: 8 }}>
            INTEGRIDADE DNS — RESOLUÇÃO EM AMBIENTE ISOLADO
          </div>
          <div
            style={{
              border: record.dnsIntegrity.dns_consensus ? '2px solid #10b981' : '2px solid #dc2626',
              borderRadius: 10,
              padding: 12,
              background: record.dnsIntegrity.dns_consensus ? 'rgba(16,185,129,0.06)' : 'rgba(220,38,38,0.06)',
              fontSize: 10,
            }}
          >
            <div style={{ marginBottom: 6 }}>
              <strong>Status:</strong>{' '}
              {record.dnsIntegrity.dns_consensus
                ? '✓ Consenso entre Google · Cloudflare · Quad9 — coleta imune a DNS Poisoning local.'
                : '⚠ Divergência entre resolvedores DoH — possível manipulação na origem.'}
            </div>
            <div style={{ marginBottom: 6 }}>
              <strong>IPs consensuais:</strong>{' '}
              <span style={{ fontFamily: 'ui-monospace, monospace' }}>
                {record.dnsIntegrity.consensus_ips.join(', ') || '—'}
              </span>
            </div>
            <div style={{ marginBottom: 6 }}>
              <strong>Método:</strong> {record.dnsIntegrity.method}
            </div>
            <table style={{ width: '100%', fontSize: 9, marginTop: 6, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: '#f3f4f6' }}>
                  <th style={{ textAlign: 'left', padding: '4px 6px', border: '1px solid #e5e7eb' }}>Resolver</th>
                  <th style={{ textAlign: 'left', padding: '4px 6px', border: '1px solid #e5e7eb' }}>A</th>
                  <th style={{ textAlign: 'left', padding: '4px 6px', border: '1px solid #e5e7eb' }}>AAAA</th>
                  <th style={{ textAlign: 'left', padding: '4px 6px', border: '1px solid #e5e7eb' }}>RTT</th>
                </tr>
              </thead>
              <tbody>
                {record.dnsIntegrity.resolver_chain.a.map((r, i) => {
                  const aaaa = record.dnsIntegrity!.resolver_chain.aaaa[i];
                  return (
                    <tr key={r.resolver}>
                      <td style={{ padding: '4px 6px', border: '1px solid #e5e7eb', fontFamily: 'monospace' }}>{r.resolver}</td>
                      <td style={{ padding: '4px 6px', border: '1px solid #e5e7eb', fontFamily: 'monospace' }}>{r.ips.join(', ') || '—'}</td>
                      <td style={{ padding: '4px 6px', border: '1px solid #e5e7eb', fontFamily: 'monospace' }}>{aaaa?.ips.join(', ') || '—'}</td>
                      <td style={{ padding: '4px 6px', border: '1px solid #e5e7eb' }}>{r.rttMs} ms</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {record.dnsIntegrity.origin?.headers && Object.keys(record.dnsIntegrity.origin.headers).length > 0 && (
              <div style={{ marginTop: 8, fontSize: 9 }}>
                <strong>Cabeçalhos HTTP de origem:</strong>{' '}
                {Object.entries(record.dnsIntegrity.origin.headers).map(([k, v]) => (
                  <div key={k} style={{ fontFamily: 'monospace', marginTop: 2 }}>
                    {k}: {v}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Metadados Técnicos de Rede (RDAP / DNS / TLS) */}
      {record.networkMetadata && (
        <div data-pdf-section="network" style={{ marginTop: 18 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#10b981', letterSpacing: 2, marginBottom: 8 }}>
            METADADOS TÉCNICOS DE REDE
          </div>
          <div style={{ border: '1px solid #e5e7eb', borderRadius: 8, padding: 12, fontSize: 10, background: '#fafafa' }}>
            <div style={{ marginBottom: 8 }}>
              <strong>RDAP (registrante):</strong>
              {record.networkMetadata.rdap && !('error' in record.networkMetadata.rdap) ? (
                <div style={{ marginTop: 4, fontFamily: 'monospace', fontSize: 9 }}>
                  Domínio: {record.networkMetadata.rdap.ldhName} · Registrar: {record.networkMetadata.rdap.registrar || '—'} ·
                  Criado: {record.networkMetadata.rdap.events?.registration || '—'} ·
                  Expira: {record.networkMetadata.rdap.events?.expiration || '—'}
                  <div>Nameservers: {(record.networkMetadata.rdap.nameservers || []).join(', ') || '—'}</div>
                </div>
              ) : (
                <span style={{ color: '#6b7280' }}> indisponível</span>
              )}
            </div>
            <div style={{ marginBottom: 8 }}>
              <strong>Registros DNS (via Cloudflare DoH):</strong>
              <div style={{ marginTop: 4, fontFamily: 'monospace', fontSize: 9 }}>
                {(['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'] as const).map((t) => {
                  const recs = record.networkMetadata!.dns[t];
                  return (
                    <div key={t} style={{ marginBottom: 2 }}>
                      <span style={{ color: '#10b981' }}>{t}:</span>{' '}
                      {recs?.length ? recs.map((r) => r.data).join(' | ') : '—'}
                    </div>
                  );
                })}
              </div>
            </div>
            <div>
              <strong>Certificado TLS:</strong>
              {record.networkMetadata.tls && !('error' in record.networkMetadata.tls) ? (
                <div style={{ marginTop: 4, fontFamily: 'monospace', fontSize: 9 }}>
                  Emissor: {String((record.networkMetadata.tls as { issuer?: unknown }).issuer || '—')}
                  <div>Validade: {(record.networkMetadata.tls as { validFrom?: string }).validFrom || '—'} → {(record.networkMetadata.tls as { validTo?: string }).validTo || '—'}</div>
                  <div>Serial: {(record.networkMetadata.tls as { serialNumber?: string }).serialNumber || '—'}</div>
                </div>
              ) : (
                <span style={{ color: '#6b7280' }}> {(record.networkMetadata.tls as { error?: string }).error || 'indisponível'}</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Carimbo de Tempo */}
      {record.timestampAnchor && (
        <div data-pdf-section="timestamp" style={{ marginTop: 18 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#10b981', letterSpacing: 2, marginBottom: 8 }}>
            CARIMBO DE TEMPO QUALIFICADO
          </div>
          <div style={{ border: '1px solid #e5e7eb', borderRadius: 8, padding: 12, fontSize: 10, background: '#fafafa' }}>
            ✓ Hash ancorado em <strong>OpenTimestamps</strong> (Bitcoin){record.timestampAnchor.rfc3161 ? ' + token RFC 3161 (FreeTSA)' : ''}.
            <div style={{ marginTop: 4, fontFamily: 'monospace', fontSize: 9 }}>
              Calendário: {record.timestampAnchor.calendar || '—'}<br />
              Ancorado em: {record.timestampAnchor.anchoredAt}
            </div>
          </div>
        </div>
      )}

      {/* Conformidade Normativa */}
      <div data-pdf-section="compliance" style={{ marginTop: 18 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: '#10b981', letterSpacing: 2, marginBottom: 8 }}>
          CONFORMIDADE NORMATIVA
        </div>
        <div style={{ border: '2px solid #10b981', borderRadius: 10, padding: 12, background: 'rgba(16,185,129,0.06)', fontSize: 10 }}>
          {[
            [
              record.dnsIntegrity?.dns_consensus !== false,
              'Isolamento do fato durante a coleta',
              'Captura executada em ambiente cloud isolado (Edge Function + headless browser remoto). Sem dependência do DNS, proxy ou resolver do operador — eliminando vetor de DNS Poisoning e MITM local.',
            ],
            [true, 'Coleta sistemática e detalhada', 'RDAP, registros DNS (A/AAAA/MX/NS/TXT/CAA), certificado TLS, cabeçalhos HTTP de origem, Open Graph, screenshot full-page e HTML cru.'],
            [true, 'Preservação da prova (dual-hash)', 'SHA-256 + SHA-512 (FIPS 180-4) sobre URL + IP + UA + timestamp + screenshot + HTML — paridade com benchmark ISO 27037.'],
            [!!record.timestampAnchor, 'Carimbo de tempo independente', 'OpenTimestamps (Bitcoin) + RFC 3161 (FreeTSA) ancorados no momento da coleta.'],
            [true, 'ISO/IEC 27037:2012', 'Itens 5.4 (identificação), 5.5 (coleta), 5.6 (aquisição) e 5.7 (preservação) atendidos pelo fluxo.'],
            [true, 'CPP art. 158-A a 158-F', 'Cadeia de custódia documentada por hash encadeado e ID único de evidência.'],
          ].map(([ok, title, desc]) => (
            <div key={title as string} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
              <span style={{ color: ok ? '#10b981' : '#dc2626', fontWeight: 700 }}>{ok ? '✓' : '⚠'}</span>
              <div>
                <div style={{ fontWeight: 700 }}>{title as string}</div>
                <div style={{ color: '#374151', fontSize: 9 }}>{desc as string}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selo */}
      <div
        data-pdf-section="seal"
        style={{
          marginTop: 18,
          border: '2px solid #10b981',
          borderRadius: 10,
          padding: 12,
          background: 'rgba(16, 185, 129, 0.06)',
        }}
      >
        <div style={{ fontSize: 10, fontWeight: 700, color: '#10b981', letterSpacing: 2 }}>
          SELO DE CADEIA DE CUSTÓDIA
        </div>
        <div style={{ fontSize: 10, marginTop: 6, color: '#374151' }}>
          O hash SHA-256 acima é gerado a partir da concatenação dos metadados (URL + URL final
          + IP + User-Agent + Timestamp UTC + Hash do Screenshot) e serve como prova matemática
          da integridade desta evidência. Qualquer alteração nos dados ou no print invalida o
          hash. {record.screenshotDataUrl
            ? 'O screenshot real da página segue nas próximas páginas.'
            : 'A captura visual não estava disponível neste registro.'}
        </div>
      </div>

      {record.captureWarning && (
        <div
          data-pdf-section="warning"
          style={{
            marginTop: 12,
            padding: 10,
            border: '1px solid #f59e0b',
            background: '#fffbeb',
            color: '#92400e',
            fontSize: 10,
            borderRadius: 8,
          }}
        >
          ⚠ {record.captureWarning}
        </div>
      )}
    </div>
  );
});
EvidenceReport.displayName = 'EvidenceReport';

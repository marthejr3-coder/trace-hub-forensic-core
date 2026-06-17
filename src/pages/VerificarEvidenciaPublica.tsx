import { Helmet } from 'react-helmet-async';
import { Link, useSearchParams } from 'react-router-dom';
import { useState } from 'react';
import { ShieldCheck, ArrowLeft, FileText, Download, Anchor, Bitcoin, Upload, Loader2, FileCheck2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import VerificarEvidencia from '@/components/juridico/VerificarEvidencia';
import TraceLogo from '@/components/TraceLogo';
import { parseOtsFile, getBitcoinTip, type OtsParseResult } from '@/lib/opentimestamps-verify';
import { toast } from 'sonner';

const REPORT_PDF = '/Relatorio_Tecnico_TraceHub.pdf';
const REPORT_HASH = 'cbe3a67387cce91e802cef4d5e2194f8c54cf0b807aed2efb35f61dbbe20f224';

export default function VerificarEvidenciaPublica() {
  const [searchParams] = useSearchParams();
  const initialHash = searchParams.get('hash') ?? undefined;
  const [otsFile, setOtsFile] = useState<File | null>(null);
  const [expectedHash, setExpectedHash] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [otsResult, setOtsResult] = useState<OtsParseResult | null>(null);
  const [btcTip, setBtcTip] = useState<{ height: number; timestamp: number } | null>(null);
  const [pdfFile, setPdfFile] = useState<File | null>(null);
  const [pdfExpectedHash, setPdfExpectedHash] = useState('');
  const [pdfHashing, setPdfHashing] = useState(false);
  const [pdfHashResult, setPdfHashResult] = useState<{ sha256: string; matches: boolean | null; size: number } | null>(null);

  const handleVerifyPdf = async () => {
    if (!pdfFile) {
      toast.error('Selecione um arquivo PDF');
      return;
    }
    setPdfHashing(true);
    try {
      const buf = await pdfFile.arrayBuffer();
      const digest = await crypto.subtle.digest('SHA-256', buf);
      const sha256 = Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const expected = pdfExpectedHash.trim().toLowerCase();
      const matches = expected.length === 64 ? sha256 === expected : null;
      setPdfHashResult({ sha256, matches, size: pdfFile.size });
      if (matches === true) toast.success('PDF íntegro — hash confere');
      else if (matches === false) toast.error('Hash DIFERENTE — PDF possivelmente adulterado');
      else toast.success('Hash calculado');
    } catch (e: any) {
      toast.error(e.message || 'Falha ao calcular hash do PDF');
    } finally {
      setPdfHashing(false);
    }
  };

  const handleVerifyOts = async () => {
    if (!otsFile) {
      toast.error('Selecione um arquivo .ots');
      return;
    }
    setVerifying(true);
    try {
      const parsed = await parseOtsFile(otsFile, expectedHash.trim() || undefined);
      const tip = await getBitcoinTip();
      setOtsResult(parsed);
      setBtcTip(tip);
      if (parsed.valid_magic) {
        toast.success('Arquivo .ots válido');
      } else {
        toast.error('Arquivo .ots não reconhecido');
      }
    } catch (e: any) {
      toast.error(e.message || 'Falha ao verificar');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <>
      <Helmet>
        <title>Verificar Evidência Forense — Trace Hub</title>
        <meta name="description" content="Validador público de hashes SHA-256 e selos OpenTimestamps de evidências digitais. Verifique a integridade de dossiês forenses Trace Hub." />
      </Helmet>

      <div className="min-h-screen bg-background">
        <header className="border-b">
          <div className="container mx-auto px-4 py-4 max-w-4xl flex items-center justify-between">
            <Link to="/">
              <TraceLogo size="sm" />
            </Link>
            <Link to="/">
              <Button variant="ghost" size="sm">
                <ArrowLeft className="w-4 h-4 mr-1.5" /> Início
              </Button>
            </Link>
          </div>
        </header>

        <main className="container mx-auto px-4 py-10 max-w-3xl">
          <div className="text-center mb-8">
            <div className="inline-flex w-14 h-14 rounded-2xl bg-emerald-500/10 items-center justify-center mb-4">
              <ShieldCheck className="w-7 h-7 text-emerald-500" />
            </div>
            <h1 className="text-3xl sm:text-4xl font-black tracking-tighter mb-2">
              Verificação Pública de Evidência
            </h1>
            <p className="text-muted-foreground max-w-xl mx-auto">
              Magistrados, peritos, advogados e demais operadores do direito podem verificar
              gratuitamente a integridade e o selo de tempo de qualquer evidência Trace Hub.
            </p>
          </div>

          <VerificarEvidencia initialHash={initialHash} />

          {/* Verificador OpenTimestamps */}
          <Card className="mt-6 border-emerald-500/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Anchor className="w-4 h-4 text-emerald-500" />
                Verificador OpenTimestamps (.ots)
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                Valide arquivos .ots gerados pelo Trace Hub ou por qualquer cliente OpenTimestamps padrão.
                A verificação é 100% client-side.
              </p>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Arquivo .ots</Label>
                <Input
                  type="file"
                  accept=".ots,application/vnd.opentimestamps"
                  onChange={(e) => setOtsFile(e.target.files?.[0] ?? null)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Hash SHA-256 original (opcional, para checar correspondência)</Label>
                <Input
                  value={expectedHash}
                  onChange={(e) => setExpectedHash(e.target.value)}
                  placeholder="64 caracteres hex"
                  className="font-mono text-xs"
                />
              </div>
              <Button onClick={handleVerifyOts} disabled={verifying || !otsFile} className="w-full">
                {verifying ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Upload className="w-4 h-4 mr-2" />}
                Verificar .ots
              </Button>

              {otsResult && (
                <div className="space-y-2 pt-3 border-t">
                  <div className="flex flex-wrap gap-2">
                    <Badge variant={otsResult.valid_magic ? 'default' : 'destructive'} className={otsResult.valid_magic ? 'bg-emerald-500' : ''}>
                      {otsResult.valid_magic ? '✓ Magic OTS válido' : '✗ Magic inválido'}
                    </Badge>
                    <Badge variant="outline">{otsResult.algorithm}</Badge>
                    {otsResult.digest_matches === true && (
                      <Badge className="bg-emerald-500">✓ Hash corresponde</Badge>
                    )}
                    {otsResult.digest_matches === false && (
                      <Badge variant="destructive">✗ Hash diferente</Badge>
                    )}
                  </div>
                  {otsResult.digest_hex && (
                    <div className="text-xs">
                      <div className="text-muted-foreground mb-0.5">Digest selado</div>
                      <code className="block font-mono text-[10px] break-all bg-muted/50 p-2 rounded">
                        {otsResult.digest_hex}
                      </code>
                    </div>
                  )}
                  <div className="text-xs">
                    <div className="text-muted-foreground mb-1">Atestações ({otsResult.attestations.length})</div>
                    <ul className="space-y-1">
                      {otsResult.attestations.map((a, i) => (
                        <li key={i} className="flex items-start gap-2 font-mono text-[11px] bg-muted/30 p-1.5 rounded">
                          <span className="text-emerald-500">{a.type === 'bitcoin' ? '₿' : a.type === 'calendar' ? '📅' : '?'}</span>
                          <span className="break-all">{a.detail}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  {btcTip && (
                    <div className="flex items-center gap-2 text-xs text-muted-foreground p-2 rounded bg-muted/30">
                      <Bitcoin className="w-3 h-3 text-amber-500" />
                      <span>
                        Bitcoin tip atual: bloco #{btcTip.height} ·{' '}
                        {new Date(btcTip.timestamp * 1000).toLocaleString('pt-BR')}
                      </span>
                    </div>
                  )}
                  <p className="text-[11px] text-muted-foreground">
                    Para auditoria completa do tree de attestations, use a CLI oficial{' '}
                    <code className="bg-muted px-1 rounded">ots verify arquivo.ots</code> em{' '}
                    <a href="https://opentimestamps.org" target="_blank" rel="noopener" className="underline text-emerald-500">
                      opentimestamps.org
                    </a>.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Verificador de SHA-256 do PDF do laudo */}
          <Card className="mt-6 border-emerald-500/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <FileCheck2 className="w-4 h-4 text-emerald-500" />
                Conferir integridade do PDF do laudo
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                Arraste qualquer PDF Trace Hub. Calculamos o SHA-256 dos bytes localmente (sem upload)
                e comparamos com o hash do sidecar <code className="px-1 bg-muted rounded">.sha256.txt</code> emitido junto com o laudo.
              </p>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Arquivo PDF</Label>
                <Input
                  type="file"
                  accept="application/pdf,.pdf"
                  onChange={(e) => { setPdfFile(e.target.files?.[0] ?? null); setPdfHashResult(null); }}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Hash esperado (opcional — cole do .sha256.txt)</Label>
                <Input
                  value={pdfExpectedHash}
                  onChange={(e) => setPdfExpectedHash(e.target.value)}
                  placeholder="64 caracteres hex"
                  className="font-mono text-xs"
                />
              </div>
              <Button onClick={handleVerifyPdf} disabled={pdfHashing || !pdfFile} className="w-full">
                {pdfHashing ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <FileCheck2 className="w-4 h-4 mr-2" />}
                Calcular SHA-256 do PDF
              </Button>
              {pdfHashResult && (
                <div className="space-y-2 pt-3 border-t">
                  <div className="flex flex-wrap gap-2">
                    {pdfHashResult.matches === true && (
                      <Badge className="bg-emerald-500">✓ PDF íntegro — hash confere</Badge>
                    )}
                    {pdfHashResult.matches === false && (
                      <Badge variant="destructive">✗ PDF adulterado — hash diferente</Badge>
                    )}
                    {pdfHashResult.matches === null && (
                      <Badge variant="outline">Hash calculado (sem comparação)</Badge>
                    )}
                    <Badge variant="outline">{(pdfHashResult.size / 1024).toFixed(1)} KB</Badge>
                  </div>
                  <div className="text-xs">
                    <div className="text-muted-foreground mb-0.5">SHA-256 do PDF</div>
                    <code className="block font-mono text-[10px] break-all bg-muted/50 p-2 rounded">
                      {pdfHashResult.sha256}
                    </code>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    Verificação 100% local — o arquivo não sai do seu navegador. Comando equivalente em terminal:{' '}
                    <code className="bg-muted px-1 rounded">sha256sum arquivo.pdf</code>
                  </p>
                </div>
              )}
            </CardContent>
          </Card>


          <Card className="mt-6 border-emerald-500/30 bg-gradient-to-br from-emerald-500/5 to-transparent">
            <CardContent className="p-5 sm:p-6">
              <div className="flex items-start gap-4">
                <div className="w-11 h-11 rounded-xl bg-emerald-500/10 flex items-center justify-center shrink-0">
                  <FileText className="w-5 h-5 text-emerald-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <h2 className="font-bold text-base sm:text-lg mb-1">Relatório Técnico-Pericial — para contestações</h2>
                  <p className="text-sm text-muted-foreground mb-3">
                    Documento metodológico oficial (v1.0, ISO/IEC 27037, NIST FIPS 180-4) para juntada aos autos quando a admissibilidade da prova for impugnada.
                  </p>
                  <div className="flex flex-col sm:flex-row gap-2">
                    <Button asChild size="sm" className="bg-emerald-500 hover:bg-emerald-600 text-white">
                      <a href={REPORT_PDF} download target="_blank" rel="noopener">
                        <Download className="w-4 h-4 mr-1.5" /> Baixar PDF
                      </a>
                    </Button>
                    <Button asChild size="sm" variant="outline">
                      <a href={REPORT_PDF} target="_blank" rel="noopener">Visualizar</a>
                    </Button>
                  </div>
                  <code className="block mt-3 text-[10px] sm:text-xs font-mono break-all text-muted-foreground bg-muted/40 p-2 rounded border">
                    SHA-256: {REPORT_HASH}
                  </code>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="mt-8 text-center text-xs text-muted-foreground">
            Plataforma de análise e proteção de evidências digitais. SHA-256 (NIST FIPS 180-4) +
            OpenTimestamps (Bitcoin) + RFC 3161 — padrões abertos amplamente aceitos pelo Judiciário.
          </div>
        </main>
      </div>
    </>
  );
}

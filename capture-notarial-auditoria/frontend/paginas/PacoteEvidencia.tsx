import { useState } from 'react';
import { Link } from "@/lib/router-compat";
import JSZip from 'jszip';
import { Check, X, FileCheck2, FileWarning, Download, ArrowLeft, ShieldCheck, Clock, FileSignature, Bitcoin } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from '@/hooks/use-toast';
import { verifyTsr, type TsrVerifyResult } from '@/lib/tsr-verify';
import { verifyOts, type OtsVerifyResult } from '@/lib/ots-verify';
import { applyPadesStamp, type PadesResult } from '@/lib/pades-stamp';
import { downloadBlob } from '@/lib/ios-download';
import SEOHead from '@/components/SEOHead';

const Step = ({ done, idx, title, children }: { done: boolean; idx: number; title: string; children: React.ReactNode }) => (
  <div className="rounded-xl border border-border bg-card p-5 sm:p-6 space-y-4">
    <div className="flex items-center gap-3">
      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${done ? 'bg-emerald-500 text-white' : 'bg-muted text-muted-foreground'}`}>
        {done ? <Check className="w-4 h-4" /> : idx}
      </div>
      <h2 className="text-base sm:text-lg font-semibold text-foreground">{title}</h2>
    </div>
    {children}
  </div>
);

const KV = ({ k, v }: { k: string; v: React.ReactNode }) => (
  <div className="flex flex-col sm:flex-row sm:gap-3 text-xs">
    <span className="text-muted-foreground sm:w-44 shrink-0">{k}</span>
    <span className="font-mono text-foreground break-all">{v}</span>
  </div>
);

/**
 * Conjunto de passos do Pacote de Evidência (TSR + OTS + PAdES).
 * Exposto como componente para ser embutido na página de Verificação Pública.
 * Passo de identidade da vítima removido.
 */
export function PacoteEvidenciaSteps() {
  // 1 — TSR
  const [tsrFile, setTsrFile] = useState<File | null>(null);
  const [tsrOriginal, setTsrOriginal] = useState<File | null>(null);
  const [tsrBusy, setTsrBusy] = useState(false);
  const [tsrResult, setTsrResult] = useState<TsrVerifyResult | null>(null);

  // 2 — OTS
  const [otsFile, setOtsFile] = useState<File | null>(null);
  const [otsOriginal, setOtsOriginal] = useState<File | null>(null);
  const [otsBusy, setOtsBusy] = useState(false);
  const [otsResult, setOtsResult] = useState<OtsVerifyResult | null>(null);

  // 3 — PAdES
  const [pdfFile, setPdfFile] = useState<File | null>(null);
  const [responsible, setResponsible] = useState('');
  const [padesBusy, setPadesBusy] = useState(false);
  const [padesResult, setPadesResult] = useState<PadesResult | null>(null);

  const checks = {
    tsr: !!tsrResult?.ok,
    ots: !!otsResult?.ok,
    pades: !!padesResult,
  };
  const allDone = checks.tsr && checks.ots && checks.pades;

  async function runTsr() {
    if (!tsrFile || !tsrOriginal) return toast({ title: 'Envie o .tsr e o arquivo original.' });
    setTsrBusy(true);
    try {
      const r = await verifyTsr(tsrFile, tsrOriginal);
      setTsrResult(r);
    } catch (e: any) {
      toast({ title: 'Falha na verificação TSR', description: e?.message || String(e), variant: 'destructive' });
    } finally { setTsrBusy(false); }
  }

  async function runOts() {
    if (!otsFile || !otsOriginal) return toast({ title: 'Envie o .ots e o arquivo original.' });
    setOtsBusy(true);
    try {
      const r = await verifyOts(otsFile, otsOriginal);
      setOtsResult(r);
    } catch (e: any) {
      toast({ title: 'Falha na verificação OTS', description: e?.message || String(e), variant: 'destructive' });
    } finally { setOtsBusy(false); }
  }

  async function runPades() {
    if (!pdfFile) return toast({ title: 'Envie o PDF do relatório.' });
    if (!responsible.trim()) return toast({ title: 'Informe o responsável pela assinatura.' });
    setPadesBusy(true);
    try {
      const r = await applyPadesStamp({ pdfFile, responsibleName: responsible });
      setPadesResult(r);
      toast({ title: 'Carimbo aplicado.' });
    } catch (e: any) {
      toast({ title: 'Falha ao aplicar carimbo', description: e?.message || String(e), variant: 'destructive' });
    } finally { setPadesBusy(false); }
  }

  async function downloadPackage() {
    const zip = new JSZip();
    if (tsrResult) zip.file('1_TSR_verification.json', JSON.stringify(tsrResult, null, 2));
    if (otsResult) zip.file('2_OTS_verification.json', JSON.stringify(otsResult, null, 2));
    if (padesResult) {
      zip.file('3_relatorio_evidencia_assinado.pdf', await padesResult.pdfBlob.arrayBuffer());
      zip.file('3_relatorio_evidencia_assinado.meta.json', JSON.stringify({
        original_sha256: padesResult.originalSha256,
        stamped_sha256: padesResult.stampedSha256,
        signed_at: padesResult.signedAt,
        verification_url: padesResult.verificationUrl,
      }, null, 2));
    }
    zip.file('MANIFEST.txt', [
      'TRACE HUB — Pacote de Evidência Digital',
      `Gerado em: ${new Date().toLocaleString('pt-BR')}`,
      '',
      `[${checks.tsr ? 'X' : ' '}] TSR verificado criptograficamente`,
      `[${checks.ots ? 'X' : ' '}] OTS confirmado na blockchain`,
      `[${checks.pades ? 'X' : ' '}] PDF assinado com carimbo`,
    ].join('\n'));
    const blob = await zip.generateAsync({ type: 'blob' });
    downloadBlob(blob, `pacote_evidencia_${Date.now()}.zip`);
  }

  return (
    <div className="space-y-5">
      <p className="text-sm text-muted-foreground">
        Complemente um pacote de evidência: verifique selos cripto e aplique carimbo no relatório PDF.
        Processamento <strong className="text-foreground">100% client-side</strong> — nenhum byte é enviado ao servidor.
      </p>

      {/* 1 TSR */}
      <Step done={checks.tsr} idx={1} title="Verificação criptográfica do .tsr (FreeTSA / RFC 3161)">
        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <Label className="text-xs">Arquivo .tsr</Label>
            <Input type="file" accept=".tsr,application/timestamp-reply" onChange={e => setTsrFile(e.target.files?.[0] || null)} />
          </div>
          <div>
            <Label className="text-xs">Arquivo original</Label>
            <Input type="file" onChange={e => setTsrOriginal(e.target.files?.[0] || null)} />
          </div>
        </div>
        <Button onClick={runTsr} disabled={tsrBusy} size="sm">
          {tsrBusy ? 'Verificando…' : 'Verificar TSR'}
        </Button>
        {tsrResult && (
          <div className={`rounded-lg border p-3 space-y-2 ${tsrResult.ok ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-destructive/40 bg-destructive/5'}`}>
            <div className="flex items-center gap-2 font-semibold text-sm">
              {tsrResult.ok ? <><FileCheck2 className="w-4 h-4 text-emerald-500" /> TSR VERIFICADO</> : <><FileWarning className="w-4 h-4 text-destructive" /> TSR INVÁLIDO</>}
            </div>
            <KV k="Hash do arquivo (SHA-256)" v={tsrResult.fileHashSha256} />
            <KV k="Hash no TSR" v={`${tsrResult.imprintHashHex || '—'} (${tsrResult.imprintAlgo})`} />
            <KV k="Match" v={tsrResult.hashMatch ? 'SIM' : 'NÃO'} />
            <KV k="Timestamp" v={tsrResult.timestampUtc || '—'} />
            <KV k="Emissor (heurístico)" v={tsrResult.issuer || '—'} />
            <KV k="tsa.crt baixado" v={tsrResult.certFetched ? `sim — fp ${tsrResult.certFingerprintSha256?.slice(0, 16)}…` : 'não'} />
            {tsrResult.notes.map((n, i) => <p key={i} className="text-[11px] text-muted-foreground italic">• {n}</p>)}
          </div>
        )}
      </Step>

      {/* 2 OTS */}
      <Step done={checks.ots} idx={2} title="Verificação do .ots (OpenTimestamps / Bitcoin)">
        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <Label className="text-xs">Arquivo .ots</Label>
            <Input type="file" accept=".ots" onChange={e => setOtsFile(e.target.files?.[0] || null)} />
          </div>
          <div>
            <Label className="text-xs">Arquivo original</Label>
            <Input type="file" onChange={e => setOtsOriginal(e.target.files?.[0] || null)} />
          </div>
        </div>
        <Button onClick={runOts} disabled={otsBusy} size="sm">
          {otsBusy ? 'Consultando calendar…' : 'Verificar OTS'}
        </Button>
        {otsResult && (
          <div className={`rounded-lg border p-3 space-y-2 ${otsResult.ok ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-amber-500/40 bg-amber-500/5'}`}>
            <div className="flex items-center gap-2 font-semibold text-sm">
              <Bitcoin className="w-4 h-4 text-amber-500" />
              {otsResult.calendarStatus === 'confirmed' ? 'CONFIRMADO NA BLOCKCHAIN' : otsResult.calendarStatus === 'pending' ? 'PENDENTE — tente novamente' : 'STATUS DESCONHECIDO'}
            </div>
            <KV k="SHA-256 do arquivo" v={otsResult.fileSha256} />
            <KV k="Digest presente no .ots" v={otsResult.digestPresent ? 'sim' : 'não'} />
            <KV k="Status calendar" v={otsResult.calendarStatus} />
            <KV k="Mensagem" v={otsResult.calendarMessage} />
            {otsResult.notes.map((n, i) => <p key={i} className="text-[11px] text-muted-foreground italic">• {n}</p>)}
          </div>
        )}
      </Step>

      {/* 3 PAdES */}
      <Step done={checks.pades} idx={3} title="Assinatura digital do relatório PDF (PAdES simulada)">
        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <Label className="text-xs">PDF do relatório</Label>
            <Input type="file" accept="application/pdf,.pdf" onChange={e => setPdfFile(e.target.files?.[0] || null)} />
          </div>
          <div>
            <Label className="text-xs">Responsável pela assinatura</Label>
            <Input value={responsible} onChange={e => setResponsible(e.target.value)} placeholder="Nome / OAB / matrícula" />
          </div>
        </div>
        <Button onClick={runPades} disabled={padesBusy} size="sm">
          <FileSignature className="w-4 h-4 mr-2" />
          {padesBusy ? 'Carimbando…' : 'Aplicar carimbo'}
        </Button>
        {padesResult && (
          <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/5 p-3 space-y-2">
            <KV k="SHA-256 original" v={padesResult.originalSha256} />
            <KV k="SHA-256 carimbado" v={padesResult.stampedSha256} />
            <KV k="URL de verificação" v={padesResult.verificationUrl} />
            <KV k="Assinado em" v={padesResult.signedAt} />
            <Button size="sm" variant="outline" onClick={() => downloadBlob(padesResult.pdfBlob, `relatorio_evidencia_assinado_${Date.now()}.pdf`)}>
              <Download className="w-4 h-4 mr-2" />Baixar PDF carimbado
            </Button>
          </div>
        )}
      </Step>

      {/* Checklist final */}
      <div className="rounded-xl border-2 border-emerald-500/40 bg-emerald-500/5 p-5 space-y-3">
        <h2 className="font-bold flex items-center gap-2"><Clock className="w-5 h-5 text-emerald-500" />Checklist final</h2>
        <ul className="space-y-2 text-sm">
          {[
            ['TSR verificado criptograficamente', checks.tsr],
            ['OTS confirmado na blockchain', checks.ots],
            ['PDF assinado com carimbo', checks.pades],
          ].map(([label, ok]) => (
            <li key={String(label)} className="flex items-center gap-2">
              {ok ? <Check className="w-4 h-4 text-emerald-500" /> : <X className="w-4 h-4 text-muted-foreground" />}
              <span className={ok ? 'text-foreground' : 'text-muted-foreground'}>{label}</span>
            </li>
          ))}
        </ul>
        <Button onClick={downloadPackage} disabled={!allDone} className="w-full" size="lg">
          <Download className="w-4 h-4 mr-2" />
          {allDone ? 'BAIXAR PACOTE COMPLETO (.zip)' : 'Complete todos os itens acima'}
        </Button>
      </div>
    </div>
  );
}

export default function PacoteEvidencia() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEOHead
        title="Pacote de Evidência — Verificação Forense — Trace Hub"
        description="Verifique um Pacote de Evidência Trace Hub: valida assinatura RFC 3161, âncora OpenTimestamps em Bitcoin e integridade PAdES do PDF."
        canonicalPath="/pacote-evidencia"
      />
      <header className="border-b border-border bg-card/50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between gap-4">
          <Link to="/verificar-evidencia" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4" /> Verificação Pública
          </Link>
          <h1 className="text-base sm:text-lg font-semibold flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-500" />
            Pacote de Evidência Digital
          </h1>
          <span />
        </div>
      </header>

      <main className="container mx-auto px-4 py-6 max-w-4xl">
        <PacoteEvidenciaSteps />
      </main>
    </div>
  );
}

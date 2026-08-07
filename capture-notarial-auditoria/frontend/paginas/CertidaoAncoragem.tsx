import { useEffect, useState } from 'react';
import { useParams, useSearchParams } from "@/lib/router-compat";
import { Loader2, ShieldCheck, Download, AlertTriangle, Clock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { supabase } from '@/integrations/supabase/client';
import { downloadCertidaoAncoragem } from '@/lib/certidao-ancoragem-pdf';
import { toast } from 'sonner';

const TOOL_LABEL: Record<string, string> = {
  ata_notarial: 'Ata Notarial Digital (Capture Notarial)',
  capture_link: 'Capture Link',
  evidence_cripto: 'Evidence Cripto',
  trace_capture: 'Trace Capture',
  gravacao_tela: 'Gravação de Tela',
};

interface AnchorRow {
  id: string;
  tool: string;
  ref_id: string | null;
  ref_label: string | null;
  evidence_hash: string;
  ots_base64: string | null;
  upgraded_ots_base64: string | null;
  tsr_base64: string | null;
  status: string;
  bitcoin_block_height: number | null;
  confirmed_at: string | null;
  created_at: string;
}

const FN_BASE = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/anchor-proof-download`;

export default function CertidaoAncoragem() {
  const { id } = useParams<{ id: string }>();
  const [params] = useSearchParams();
  const token = params.get('token') ?? '';
  const [loading, setLoading] = useState(true);
  const [anchor, setAnchor] = useState<AnchorRow | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.title = 'Certidão de Ancoragem Bitcoin | Trace Hub';
    let cancelled = false;
    (async () => {
      if (!id || !token) {
        setError('Link inválido ou incompleto. Use o link recebido por e-mail.');
        setLoading(false);
        return;
      }
      try {
        const res = await fetch(`${FN_BASE}?id=${encodeURIComponent(id)}&token=${encodeURIComponent(token)}&mode=data`);
        const json = await res.json();
        if (!res.ok) throw new Error(json?.error || 'Falha ao carregar a ancoragem.');
        if (!cancelled) setAnchor(json.anchor as AnchorRow);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [id, token]);

  const confirmed = !!anchor?.bitcoin_block_height;

  const handleCertidao = () => {
    if (!anchor) return;
    try {
      downloadCertidaoAncoragem({
        evidenceHash: anchor.evidence_hash,
        subject: anchor.ref_label,
        createdAt: anchor.created_at,
        stamp: {
          status: anchor.status,
          ots_base64: anchor.upgraded_ots_base64 ?? anchor.ots_base64,
          bitcoin_block_height: anchor.bitcoin_block_height,
          ots_confirmed_at: anchor.confirmed_at,
          created_at: anchor.created_at,
        },
      });
    } catch (e: any) {
      toast.error(e?.message || 'Falha ao gerar a certidão.');
    }
  };

  const fileUrl = (mode: 'ots' | 'tsr') =>
    `${FN_BASE}?id=${encodeURIComponent(id ?? '')}&token=${encodeURIComponent(token)}&mode=${mode}`;

  return (
    <main className="min-h-screen bg-background py-10 px-4">
      <div className="max-w-2xl mx-auto space-y-6">
        <header className="text-center space-y-2">
          <h1 className="text-2xl font-bold flex items-center justify-center gap-2">
            <ShieldCheck className="w-6 h-6 text-primary" />
            Certidão de Ancoragem Bitcoin
          </h1>
          <p className="text-sm text-muted-foreground">
            Documento complementar ao relatório já emitido. Os hashes originais permanecem inalterados.
          </p>
        </header>

        {loading && (
          <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground">
            <Loader2 className="w-5 h-5 animate-spin" /> Carregando ancoragem…
          </div>
        )}

        {!loading && error && (
          <Card className="border-destructive/40">
            <CardContent className="pt-6 flex items-start gap-3 text-sm">
              <AlertTriangle className="w-5 h-5 text-destructive shrink-0" />
              <span>{error}</span>
            </CardContent>
          </Card>
        )}

        {!loading && anchor && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between gap-3 text-base">
                <span>{TOOL_LABEL[anchor.tool] ?? anchor.tool}</span>
                {confirmed ? (
                  <Badge className="bg-emerald-600 hover:bg-emerald-600">Confirmado em bloco</Badge>
                ) : (
                  <Badge variant="secondary" className="gap-1">
                    <Clock className="w-3 h-3" /> Aguardando bloco
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              <dl className="space-y-2">
                {anchor.ref_label && (
                  <div>
                    <dt className="text-xs text-muted-foreground">Caso</dt>
                    <dd className="font-medium">{anchor.ref_label}</dd>
                  </div>
                )}
                <div>
                  <dt className="text-xs text-muted-foreground">Hash SHA-256 da evidência</dt>
                  <dd className="font-mono text-xs break-all">{anchor.evidence_hash}</dd>
                </div>
                {confirmed && (
                  <div>
                    <dt className="text-xs text-muted-foreground">Bloco Bitcoin</dt>
                    <dd className="font-medium">
                      #{anchor.bitcoin_block_height}{' '}
                      <a
                        className="text-primary underline"
                        href={`https://mempool.space/block/${anchor.bitcoin_block_height}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        ver no explorador
                      </a>
                    </dd>
                  </div>
                )}
                {anchor.confirmed_at && (
                  <div>
                    <dt className="text-xs text-muted-foreground">Confirmado em</dt>
                    <dd>{new Date(anchor.confirmed_at).toLocaleString('pt-BR')}</dd>
                  </div>
                )}
              </dl>

              <div className="flex flex-col sm:flex-row gap-2 pt-2">
                <Button type="button" onClick={handleCertidao} className="gap-2">
                  <Download className="w-4 h-4" /> Baixar certidão (PDF)
                </Button>
                {(anchor.upgraded_ots_base64 || anchor.ots_base64) && (
                  <Button type="button" variant="outline" asChild>
                    <a href={fileUrl('ots')}>Baixar .ots atualizado</a>
                  </Button>
                )}
                {anchor.tsr_base64 && (
                  <Button type="button" variant="outline" asChild>
                    <a href={fileUrl('tsr')}>Baixar .tsr (RFC 3161)</a>
                  </Button>
                )}
              </div>

              <p className="text-xs text-muted-foreground">
                Verificação independente pela CLI oficial: <code>ots verify ancoragem.ots</code>.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </main>
  );
}

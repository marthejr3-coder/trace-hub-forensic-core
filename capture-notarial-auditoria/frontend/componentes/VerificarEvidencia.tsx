import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ShieldCheck, Loader2, CheckCircle2, XCircle, FileText, Calendar, MapPin } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { formatHashForDisplay } from '@/lib/forensic-hash';
import { getReportTypeLabel } from '@/lib/forensic-seal';
import { useEffect } from 'react';

interface VerificationResult {
  valid: boolean;
  capturedAt?: string;
  type?: string;
  subject?: string | null;
  city?: string | null;
  country?: string | null;
}

interface VerificarEvidenciaProps {
  /** Se fornecido, valida automaticamente ao montar (uso via ?hash= na URL pública). */
  initialHash?: string;
}

export default function VerificarEvidencia({ initialHash }: VerificarEvidenciaProps = {}) {
  const [hash, setHash] = useState(initialHash ?? '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);

  const runVerify = async (rawHash: string) => {
    const clean = rawHash.trim().toLowerCase().replace(/[:\s]/g, '');
    if (!/^[a-f0-9]{64}$/.test(clean)) {
      toast.error('Hash SHA-256 inválido (deve ter 64 caracteres hexadecimais)');
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const { data, error } = await (supabase.rpc as any)('verify_forensic_report', {
        hash_to_verify: clean,
      });
      if (error) throw error;
      const row = Array.isArray(data) ? data[0] : data;
      if (row?.found) {
        setResult({
          valid: true,
          capturedAt: row.captured_at,
          type: getReportTypeLabel(row.report_type),
          subject: row.subject,
          city: row.city,
          country: row.country,
        });
        toast.success('Evidência válida e íntegra');
      } else {
        setResult({ valid: false });
        toast.error('Hash não encontrado em nossa base');
      }
    } catch (e: any) {
      toast.error(e.message || 'Erro ao verificar');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = () => runVerify(hash);

  useEffect(() => {
    if (initialHash && /^[a-f0-9]{64}$/i.test(initialHash.replace(/[:\s]/g, ''))) {
      runVerify(initialHash);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialHash]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-500" />
          Validador de Evidências Forenses
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          Confira a integridade e autenticidade de qualquer evidência gerada pela Trace Hub
          informando o hash SHA-256 do dossiê.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label>Hash SHA-256</Label>
          <div className="flex gap-2">
            <Input
              placeholder="ex: a3f5b8c1e2d4..."
              value={hash}
              onChange={(e) => setHash(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleVerify()}
              className="font-mono text-xs"
            />
            <Button onClick={handleVerify} disabled={loading}>
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              <span className="ml-2 hidden sm:inline">Verificar</span>
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            64 caracteres hexadecimais. Aceita também formato com separadores (a3:f5:b8...).
          </p>
        </div>

        {result && (
          result.valid ? (
            <div className="p-5 rounded-lg border-2 border-emerald-500/30 bg-emerald-500/5 space-y-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-8 h-8 text-emerald-500" />
                <div>
                  <p className="font-bold text-emerald-600 dark:text-emerald-400">Evidência Autêntica</p>
                  <p className="text-xs text-muted-foreground">
                    Hash registrado e íntegro nos sistemas Trace Hub
                  </p>
                </div>
              </div>

              <div className="grid sm:grid-cols-2 gap-3 pt-2 border-t border-emerald-500/20">
                <div>
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
                    <FileText className="w-3 h-3" /> Tipo
                  </div>
                  <p className="text-sm font-medium">{result.type}</p>
                </div>
                <div>
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
                    <Calendar className="w-3 h-3" /> Captura
                  </div>
                  <p className="text-sm font-medium">
                    {result.capturedAt ? new Date(result.capturedAt).toLocaleString('pt-BR') : '—'}
                  </p>
                </div>
                {(result.city || result.country) && (
                  <div className="sm:col-span-2">
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
                      <MapPin className="w-3 h-3" /> Local da captura
                    </div>
                    <p className="text-sm font-medium">
                      {[result.city, result.country].filter(Boolean).join(', ')}
                    </p>
                  </div>
                )}
                <div className="sm:col-span-2">
                  <div className="text-xs text-muted-foreground mb-1">Hash verificado</div>
                  <p className="text-[11px] font-mono break-all bg-background/50 p-2 rounded border">
                    {formatHashForDisplay(hash.trim().toLowerCase().replace(/[:\s]/g, ''))}
                  </p>
                </div>
              </div>

              <Badge variant="outline" className="border-emerald-500/40 text-emerald-600 dark:text-emerald-400">
                SHA-256 · Cadeia de custódia preservada
              </Badge>
            </div>
          ) : (
            <div className="p-5 rounded-lg border-2 border-destructive/30 bg-destructive/5 flex items-start gap-3">
              <XCircle className="w-8 h-8 text-destructive flex-shrink-0" />
              <div>
                <p className="font-bold text-destructive">Hash não localizado</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Este hash não corresponde a nenhuma evidência registrada na Trace Hub.
                  Verifique se foi copiado corretamente, ou solicite o dossiê original ao operador
                  responsável pela investigação.
                </p>
              </div>
            </div>
          )
        )}

        <div className="text-[11px] text-muted-foreground border-t pt-3">
          <strong>Como funciona:</strong> Toda captura realizada pela Trace Hub gera um hash SHA-256
          imutável dos dados coletados (IP, geolocalização, fingerprint, timestamp). Este hash é
          armazenado no momento da coleta. Se o conteúdo do dossiê for alterado, o hash recalculado
          será diferente — provando a quebra da cadeia de custódia.
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * CSAMSecondaryAttestationCard — Two-person sign-off (opcional).
 *
 * Padrão ICAC: um segundo operador valida a sessão (via 2º device, mesma plataforma)
 * lendo o QR do integrity_hash do laudo e gerando uma sub-assinatura SHA-256
 * com nonce + timestamp próprios. Anexada como §5.3 do laudo final.
 *
 * Fluxo solo (perito sozinho): toggle desligado, card recolhido.
 */
import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Users, ShieldCheck, Loader2 } from 'lucide-react';
// generateSHA256 não é mais usado: signoff_hash é recalculado server-side (N-01).
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import type { SecondaryAttestation } from '@/lib/csam-preliminary-report';

interface Props {
  sessionId: string;
  primaryIntegrityHash: string | null;
  primaryOperatorEmail?: string | null;
  onAttestation: (a: SecondaryAttestation | null) => void;
}

export default function CSAMSecondaryAttestationCard({
  sessionId, primaryIntegrityHash, primaryOperatorEmail, onAttestation,
}: Props) {
  const [enabled, setEnabled] = useState(false);
  const [secondaryEmail, setSecondaryEmail] = useState('');
  const [notes, setNotes] = useState('');
  const [signing, setSigning] = useState(false);
  const [signed, setSigned] = useState<SecondaryAttestation | null>(null);
  const [qrUrl, setQrUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled || !primaryIntegrityHash) { setQrUrl(null); return; }
    const payload = JSON.stringify({
      type: 'csam_session_attestation_request',
      session_id: sessionId,
      integrity_hash: primaryIntegrityHash,
      primary_operator: primaryOperatorEmail ?? null,
      ts: new Date().toISOString(),
    });
    import('qrcode')
      .then((m) => (m.default ?? m).toDataURL(payload, { margin: 1, width: 220 }))
      .then(setQrUrl)
      .catch(() => setQrUrl(null));
  }, [enabled, primaryIntegrityHash, sessionId, primaryOperatorEmail]);

  const canSign = enabled && !!primaryIntegrityHash && secondaryEmail.trim().length > 3 && !signing && !signed;

  const handleSign = async () => {
    if (!primaryIntegrityHash) return;
    setSigning(true);
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) { toast.error('Sessão expirada'); return; }

      // Guard client-side (UX); o gate real é server-side na Edge Function (N-01).
      const nonceArr = new Uint8Array(16);
      crypto.getRandomValues(nonceArr);
      const nonce = Array.from(nonceArr).map((b) => b.toString(16).padStart(2, '0')).join('');
      const deviceFp = `${navigator.userAgent.slice(0, 80)} · ${screen.width}x${screen.height}`;

      const { data, error } = await supabase.functions.invoke('csam-secondary-signoff', {
        body: {
          session_id: sessionId,
          secondary_email: secondaryEmail.trim(),
          attested_integrity_hash: primaryIntegrityHash,
          signoff_nonce: nonce,
          device_fingerprint: deviceFp,
          notes: notes.trim() || null,
        },
      });
      if (error || !data?.ok) {
        const code = (data as any)?.code || (error as any)?.context?.body?.code;
        if (code === 'SAME_OPERATOR') {
          toast.error('O 2º operador precisa ser uma conta diferente do operador primário. Faça login em outra conta/dispositivo.');
        } else {
          toast.error('Falha no sign-off: ' + (data?.error || error?.message || 'erro desconhecido'));
        }
        return;
      }

      const att: SecondaryAttestation = {
        secondary_operator_id: user.id,
        secondary_operator_email: secondaryEmail.trim(),
        attested_integrity_hash: primaryIntegrityHash,
        signoff_hash: data.signoff_hash,
        signoff_nonce: nonce,
        signed_at: data.signed_at,
        device_fingerprint: deviceFp,
        notes: notes.trim() || null,
      };
      setSigned(att);
      onAttestation(att);
      toast.success('Sign-off do 2º operador registrado');
    } catch (e: any) {
      toast.error('Falha no sign-off: ' + (e?.message || String(e)));
    } finally {
      setSigning(false);
    }
  };


  const toggleEnabled = (v: boolean) => {
    setEnabled(v);
    if (!v) {
      setSigned(null);
      onAttestation(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Users className="h-4 w-4" /> Sign-off de 2º operador (opcional)
            </CardTitle>
            <CardDescription>
              Padrão ICAC. Segundo operador valida a sessão pelo seu próprio dispositivo, lendo o QR do hash de integridade.
            </CardDescription>
          </div>
          <Switch checked={enabled} onCheckedChange={toggleEnabled} aria-label="Ativar sign-off duplo" />
        </div>
      </CardHeader>
      {enabled && (
        <CardContent className="space-y-4">
          {!primaryIntegrityHash && (
            <Alert>
              <AlertTitle>Aguardando hash do laudo</AlertTitle>
              <AlertDescription className="text-xs">
                Gere o laudo preliminar primeiro — o hash final é o que o 2º operador vai atestar.
              </AlertDescription>
            </Alert>
          )}
          {primaryIntegrityHash && qrUrl && (
            <div className="flex flex-col sm:flex-row gap-4 items-start">
              <img src={qrUrl} alt="QR de atestação" className="w-40 h-40 border border-border rounded" />
              <div className="text-xs text-muted-foreground space-y-1 flex-1">
                <p><strong className="text-foreground">2º operador:</strong> abra o Trace Hub no seu dispositivo, entre em <em>CSAM → Validar sessão</em> e leia este QR.</p>
                <p>Hash atestado: <code className="font-mono text-[10px]">{primaryIntegrityHash.slice(0, 32)}…</code></p>
              </div>
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="sec-email">E-mail do 2º operador</Label>
              <Input
                id="sec-email"
                type="email"
                placeholder="perito.duplo@orgao.gov.br"
                value={secondaryEmail}
                onChange={(e) => setSecondaryEmail(e.target.value)}
                disabled={!!signed}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="sec-notes">Observações (opcional)</Label>
              <Textarea
                id="sec-notes"
                rows={1}
                placeholder="Ex.: Acompanhamento presencial em sala segura."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                disabled={!!signed}
              />
            </div>
          </div>
          {signed ? (
            <Alert className="border-emerald-500/40">
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
              <AlertTitle className="text-emerald-700 dark:text-emerald-400">Sign-off registrado</AlertTitle>
              <AlertDescription className="text-xs space-y-1">
                <div>Operador: <code className="font-mono">{signed.secondary_operator_email}</code></div>
                <div>Hash do sign-off: <code className="font-mono text-[10px]">{signed.signoff_hash.slice(0, 32)}…</code></div>
                <div>Será incluído na §5.3 do laudo final.</div>
              </AlertDescription>
            </Alert>
          ) : (
            <Button onClick={handleSign} disabled={!canSign} className="w-full">
              {signing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <ShieldCheck className="h-4 w-4 mr-2" />}
              Assinar como 2º operador
            </Button>
          )}
          <p className="text-[10px] text-muted-foreground">
            Tudo é local + DB do Trace Hub. Nenhuma mídia é transmitida — só o hash final do laudo.
          </p>
          <p className="text-[10px] text-muted-foreground border-t border-border pt-2">
            <strong>Device fingerprint:</strong> informação declaratória do dispositivo (User-Agent + resolução),
            <em> não verificada criptograficamente</em>. Para evidência de nível alto, use 2º fator FIDO2/WebAuthn.
            O gate de identidade distinta (2º operador ≠ primário) é validado server-side.
          </p>
        </CardContent>
      )}
    </Card>
  );
}



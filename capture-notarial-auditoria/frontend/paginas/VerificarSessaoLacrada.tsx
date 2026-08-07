import { useState } from "react";
import { Helmet } from '@/lib/helmet-compat';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, CheckCircle2, FileArchive, Loader2, Search, ShieldCheck, XCircle } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { verifySealedForensicPackage, type SealedPackageVerification } from "@/lib/forensic-integrity";

interface SessionIntegrity {
  session_id: string;
  started_at: string | null;
  ended_at: string | null;
  status: string | null;
  merkle_root: string | null;
  master_hash: string | null;
  originstamp_id: string | null;
  environment_tampered: boolean | null;
  forensic_status: string | null;
  event_count: number | null;
  dom_snapshot_count: number | null;
  mutation_count: number | null;
  tamper_event_count: number | null;
}

const VERDICT_LABEL: Record<string, string> = {
  integra: "Íntegra",
  integra_com_ressalvas: "Íntegra com ressalvas",
  comprometida: "Comprometida",
};

export default function VerificarSessaoLacrada() {
  const [file, setFile] = useState<File | null>(null);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<SealedPackageVerification | null>(null);
  const [sessionId, setSessionId] = useState("");
  const [lookingUp, setLookingUp] = useState(false);
  const [session, setSession] = useState<SessionIntegrity | null>(null);

  async function handleVerify() {
    if (!file) return;
    setChecking(true);
    setResult(null);
    try {
      const verification = await verifySealedForensicPackage(file);
      setResult(verification);
      if (verification.ok) toast.success("Pacote íntegro — todas as verificações fecharam.");
      else toast.error("Divergências encontradas no pacote.");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Não foi possível ler o pacote.");
    } finally {
      setChecking(false);
    }
  }

  async function handleLookup() {
    const id = sessionId.trim();
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      toast.error("Informe o identificador da sessão (UUID).");
      return;
    }
    setLookingUp(true);
    setSession(null);
    try {
      const { data, error } = await supabase.rpc("get_sealed_session_integrity", { _session_id: id });
      if (error) throw error;
      const row = Array.isArray(data) ? (data[0] as SessionIntegrity | undefined) : (data as SessionIntegrity | null);
      if (!row) {
        toast.error("Sessão não encontrada ou ainda não selada.");
        return;
      }
      setSession(row);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Falha na consulta.");
    } finally {
      setLookingUp(false);
    }
  }

  const Row = ({ label, value, ok }: { label: string; value: string; ok?: boolean }) => (
    <div className="flex items-start justify-between gap-3 py-1.5 border-b border-border/50 last:border-0">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-xs font-mono break-all text-right flex items-center gap-1.5">
        {ok === true && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />}
        {ok === false && <XCircle className="w-3.5 h-3.5 text-destructive shrink-0" />}
        {value}
      </span>
    </div>
  );

  return (
    <div className="min-h-screen bg-background py-10 px-4">
      <Helmet>
        <title>Verificar Sessão Lacrada | Trace Hub</title>
        <meta
          name="description"
          content="Verificação independente do pacote de integridade de uma captura lacrada: master hash, cadeia de eventos, cadeia de DOM e hashes dos artefatos, tudo no seu navegador."
        />
        <link rel="canonical" href="https://www.trace-hub.com/verificar-sessao-lacrada" />
      </Helmet>

      <div className="max-w-3xl mx-auto space-y-6">
        <header className="text-center space-y-2">
          <ShieldCheck className="w-10 h-10 text-primary mx-auto" />
          <h1 className="text-2xl font-bold">Verificação independente de sessão lacrada</h1>
          <p className="text-sm text-muted-foreground">
            A conferência é feita integralmente no seu navegador. O pacote não é enviado a nenhum servidor.
          </p>
        </header>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <FileArchive className="w-4 h-4" /> Modo verificador offline
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              type="file"
              accept=".zip,application/zip"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
                setResult(null);
              }}
            />
            <Button onClick={handleVerify} disabled={!file || checking} className="w-full">
              {checking ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <ShieldCheck className="w-4 h-4 mr-2" />}
              Verificar pacote
            </Button>

            {result && (
              <div className="rounded-lg border border-border p-3 space-y-1">
                <div className="flex items-center gap-2 pb-2">
                  {result.ok ? (
                    <Badge className="bg-emerald-600 text-white">Pacote íntegro</Badge>
                  ) : (
                    <Badge variant="destructive">Divergências encontradas</Badge>
                  )}
                </div>
                <Row
                  label="Master Hash (recalculado)"
                  value={result.master_hash.expected || "—"}
                  ok={result.master_hash.valid}
                />
                <Row
                  label="Cadeia de eventos"
                  value={
                    result.event_chain.valid
                      ? `${result.event_chain.count} elo(s) válido(s)`
                      : `rompida no elo ${result.event_chain.brokenAt}`
                  }
                  ok={result.event_chain.valid}
                />
                <Row
                  label="Cadeia de DOM"
                  value={
                    result.dom_chain.valid
                      ? `${result.dom_chain.count} elo(s) válido(s)`
                      : `rompida no elo ${result.dom_chain.brokenAt}`
                  }
                  ok={result.dom_chain.valid}
                />
                <Row
                  label="Cadeia de quadros do vídeo"
                  value={
                    result.frame_chain.count === 0
                      ? "não presente neste pacote"
                      : result.frame_chain.valid
                        ? `${result.frame_chain.count} quadro(s) encadeado(s)`
                        : `rompida no elo ${result.frame_chain.brokenAt}`
                  }
                  ok={result.frame_chain.count === 0 ? undefined : result.frame_chain.valid}
                />
                {result.observation && (
                  <Row
                    label="Escopo de observação"
                    value={
                      (result.observation.scope === "observed" ? "Observada (DOM monitorado)" : "Pixel-only") +
                      (result.observation.surface_anomaly
                        ? " — anomalia de superfície registrada (indício de inspetor aberto na aba alvo)"
                        : "")
                    }
                    ok={result.observation.surface_anomaly ? false : undefined}
                  />
                )}
                {result.files.map((f) => (
                  <Row key={f.file_name} label={f.file_name} value={f.computed ?? "arquivo ausente"} ok={f.valid} />
                ))}
                {result.errors.length > 0 && (
                  <div className="pt-2 text-xs text-amber-500 space-y-1">
                    {result.errors.map((err) => (
                      <p key={err} className="flex items-start gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                        {err}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Search className="w-4 h-4" /> Conferir o registro público da sessão
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex gap-2">
              <Input
                placeholder="Identificador da sessão (UUID)"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
              />
              <Button onClick={handleLookup} disabled={lookingUp} variant="outline">
                {lookingUp ? <Loader2 className="w-4 h-4 animate-spin" /> : "Consultar"}
              </Button>
            </div>
            {session && (
              <div className="rounded-lg border border-border p-3">
                <Row label="Situação forense" value={VERDICT_LABEL[session.forensic_status ?? ""] ?? "—"} />
                <Row label="Master Hash registrado" value={session.master_hash ?? "—"} />
                <Row label="Raiz Merkle dos eventos" value={session.merkle_root ?? "—"} />
                <Row label="Ancoragem (OriginStamp)" value={session.originstamp_id ?? "pendente"} />
                <Row label="Eventos" value={String(session.event_count ?? 0)} />
                <Row label="Snapshots de DOM" value={String(session.dom_snapshot_count ?? 0)} />
                <Row label="Mutações" value={String(session.mutation_count ?? 0)} />
                <Row
                  label="Ambiente adulterado"
                  value={session.environment_tampered ? `sim (${session.tamper_event_count ?? 0} evento(s))` : "não"}
                  ok={!session.environment_tampered}
                />
                <p className="text-[10px] text-muted-foreground pt-2">
                  A consulta pública expõe apenas metadados de integridade — nunca o conteúdo capturado.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// build-force 2026-07-18T18:00:00Z
/**
 * Lista as Atas Notariais Digitais do usuário atual para permitir
 * reabrir um laudo passado e atualizar a ancoragem Bitcoin (OpenTimestamps),
 * mesmo depois de fechar a janela original do relatório.
 */
import { useEffect, useRef, useState } from 'react';
import { Loader2, RotateCcw, FileSignature, History, Bitcoin, CheckCircle2, AlertTriangle, Send, FileDown } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { supabase } from '@/integrations/supabase/client';
import { downloadCertidaoAncoragem } from '@/lib/certidao-ancoragem-pdf';

type Phase = 'idle' | 'sending' | 'processing' | 'confirmed' | 'failed';
const POLL_INTERVAL_MS = 5 * 60 * 1000; // 5 min: confirmação Bitcoin leva 1–6h


interface Row {
  evidence_hash: string;
  subject: string | null;
  metadata: any;
  created_at: string;
}

interface Props {
  onReopen: (payload: { result: any; stamp: any; sealedResult: any; otsStatus: any }) => void;
}

function buildOtsStatus(stamp: any) {
  if (!stamp) return null;
  return {
    confirmed: stamp.status === 'confirmed_bitcoin',
    confirmedAt: stamp.ots_confirmed_at ?? null,
    blockHeight: stamp.bitcoin_block_height ?? null,
  };
}

/** Garante que campos usados pelo renderizador existam, mesmo em laudos antigos. */
function normalizeResult(res: any, r: Row): any {
  const meta = r.metadata ?? {};
  return {
    ...res,
    original_url: res.original_url ?? meta.original_url ?? '',
    final_url: res.final_url ?? meta.final_url ?? res.original_url ?? '',
    page_title: res.page_title ?? r.subject ?? '',
    timestamp: res.timestamp ?? r.created_at,
    timestamp_source: res.timestamp_source ?? meta.timestamp_source ?? null,
    http_status: typeof res.http_status === 'number' ? res.http_status : 0,
    http_headers: res.http_headers ?? {},
    html_hash: res.html_hash ?? meta.html_hash ?? '',
    html_size: typeof res.html_size === 'number' ? res.html_size : 0,
    screenshot_base64: res.screenshot_base64 ?? null,
    screenshot_mime: res.screenshot_mime ?? meta.screenshot_mime ?? null,
    screenshot_hash: res.screenshot_hash ?? meta.screenshot_hash ?? null,
    evidence_hash: res.evidence_hash ?? r.evidence_hash,
    dnsIntegrity: res.dnsIntegrity ?? null,
    networkMetadata: res.networkMetadata ?? null,
    captureEnv: res.captureEnv ?? null,
    merkle: res.merkle ?? null,
  };
}

/** Laudos antigos não guardaram o payload completo — só cabe certidão. */
function hasFullPayload(r: Row): boolean {
  return !!r.metadata?.result;
}

function reopenPayloadFrom(r: Row, stampOverride?: any, restoredResult?: any) {
  const meta = r.metadata ?? {};
  const stamp = stampOverride ?? meta.stamp ?? null;
  const sealed = meta.sealed_stamp ?? null;
  const base = restoredResult ?? meta.result ?? { evidence_hash: r.evidence_hash };
  return {
    result: normalizeResult(base, r),
    stamp,
    sealedResult: sealed,
    otsStatus: buildOtsStatus(stamp),
  };
}



export default function RecentNotarialReports({ onReopen }: Props) {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [phase, setPhase] = useState<Record<string, Phase>>({});
  const [lastPollAt, setLastPollAt] = useState<Date | null>(null);
  // Selos vindos da tabela append-only `forensic_report_stamps` (último por hash).
  const [stamps, setStamps] = useState<Record<string, any>>({});
  const pollingRef = useRef<number | null>(null);
  const [reopening, setReopening] = useState<string | null>(null);

  // Reabre a ata restaurando o payload completo persistido em metadata.result
  // e rebaixando o screenshot do bucket privado (não vai no JSON por peso).
  async function handleReopen(r: Row) {
    const evHash = r.evidence_hash;
    setReopening(evHash);
    try {
      const persisted = await confirmPersistedStamp(evHash, { silent: true });
      const meta = r.metadata ?? {};
      const restored: any = { ...(meta.result ?? {}) };

      if (meta.screenshot_path) {
        try {
          const { data: blob, error } = await supabase.storage
            .from('notarial-screenshots')
            .download(meta.screenshot_path);
          if (error) throw error;
          if (blob) {
            const buf = new Uint8Array(await blob.arrayBuffer());
            let bin = '';
            const chunk = 0x8000;
            for (let i = 0; i < buf.length; i += chunk) {
              bin += String.fromCharCode(...buf.subarray(i, i + chunk));
            }
            restored.screenshot_base64 = btoa(bin);
            restored.screenshot_mime = meta.screenshot_mime ?? blob.type ?? 'image/png';
          }
        } catch (err) {
          console.warn('[RecentNotarialReports] screenshot indisponível', err);
          toast.info('Captura de tela indisponível', {
            description: 'O laudo será reaberto sem a imagem; os hashes e demais seções permanecem íntegros.',
          });
        }
      }

      const payload = reopenPayloadFrom(r, persisted ?? stampOf(r), restored);
      onReopen(payload);
      const label = persisted?.bitcoin_block_height
        ? `bloco Bitcoin #${persisted.bitcoin_block_height}`
        : persisted?.ots_base64
        ? 'selo ancorado, sem bloco Bitcoin ainda'
        : 'sem selo persistido';
      toast.success('Ata reaberta', {
        description: `Estado no banco: ${label}. Role até "Ancoragem Bitcoin" para regerar o PDF.`,
      });
    } catch (err: any) {
      console.error('[RecentNotarialReports] reopen failed', err);
      toast.error('Falha ao reabrir ata', { description: err?.message || String(err) });
    } finally {
      setReopening(null);
    }
  }

  // Laudos antigos (sem metadata.result) não podem ser reabertos fielmente:
  // emite-se a Certidão de Ancoragem, que certifica hash, data e bloco Bitcoin.
  async function handleCertidao(r: Row) {
    try {
      const persisted = (await confirmPersistedStamp(r.evidence_hash, { silent: true })) ?? stampOf(r);
      const meta = r.metadata ?? {};
      downloadCertidaoAncoragem({
        evidenceHash: r.evidence_hash,
        subject: r.subject,
        originalUrl: meta.original_url ?? null,
        finalUrl: meta.final_url ?? null,
        createdAt: r.created_at,
        stamp: persisted,
        operatorName: meta.requester_snapshot?.name ?? null,
        operatorEmail: meta.requester_email ?? null,
      });
      toast.success('Certidão de Ancoragem emitida', {
        description: 'Esta ata foi criada antes da persistência do laudo completo; a certidão comprova hash, data e bloco Bitcoin.',
      });
    } catch (err: any) {
      toast.error('Falha ao emitir certidão', { description: err?.message || String(err) });
    }
  }



  // O laudo (`forensic_reports`) é WORM/append-only: qualquer UPDATE é bloqueado
  // por trigger. Por isso o selo vive em eventos append-only à parte.
  const stampOf = (r: Row) => stamps[r.evidence_hash] ?? r.metadata?.stamp ?? null;

  async function loadStamps(hashes: string[]) {
    if (hashes.length === 0) { setStamps({}); return {} as Record<string, any>; }
    const { data, error } = await (supabase.from('forensic_report_stamps') as any)
      .select('evidence_hash, payload, created_at')
      .eq('kind', 'stamp')
      .in('evidence_hash', hashes)
      .order('created_at', { ascending: false });
    if (error) {
      console.error('[RecentNotarialReports] loadStamps failed', error);
      return {} as Record<string, any>;
    }
    const latest: Record<string, any> = {};
    for (const row of (data ?? []) as any[]) {
      if (!latest[row.evidence_hash]) latest[row.evidence_hash] = row.payload;
    }
    setStamps(latest);
    return latest;
  }

  // Grava um novo evento de selo (append-only). Lança erro visível se o insert
  // não retornar linha (RLS/sessão).
  async function saveStamp(evHash: string, stamp: any) {
    const { data: userResp } = await supabase.auth.getUser();
    const userId = userResp?.user?.id;
    if (!userId) throw new Error('Sessão expirada — faça login novamente para gravar o selo.');
    const { data: inserted, error } = await (supabase.from('forensic_report_stamps') as any)
      .insert({
        user_id: userId,
        evidence_hash: evHash,
        kind: 'stamp',
        payload: stamp,
        status: stamp?.status ?? null,
        bitcoin_block_height: stamp?.bitcoin_block_height ?? null,
      })
      .select('id');
    if (error) throw error;
    if (!inserted || (Array.isArray(inserted) && inserted.length === 0)) {
      throw new Error('Selo não gravado — verifique se você está logado com a conta que criou a ata (RLS).');
    }
    setStamps((s) => ({ ...s, [evHash]: stamp }));
    return stamp;
  }

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await (supabase.from('forensic_reports') as any)
        .select('evidence_hash, subject, metadata, created_at')
        .eq('report_type', 'notarial')
        .order('created_at', { ascending: false })
        .limit(20);
      const list = (data as Row[]) ?? [];
      setRows(list);
      await loadStamps(list.map((r) => r.evidence_hash));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);



  // Polling automático: a cada 5 min verifica silenciosamente todas as linhas
  // "processing" (ancoradas mas ainda sem bloco Bitcoin). Para quando não há
  // mais nada para acompanhar. Pausado quando a aba está em background.
  useEffect(() => {
    if (!rows || rows.length === 0) return;
    const pending = rows.filter((r) => {
      const s = stampOf(r);
      return s?.ots_base64 && s?.status !== 'confirmed_bitcoin';
    });

    if (pending.length === 0) {
      if (pollingRef.current) { window.clearInterval(pollingRef.current); pollingRef.current = null; }
      return;
    }
    if (pollingRef.current) return; // já ativo
    const tick = async () => {
      if (document.hidden) return;
      for (const r of pending) {
        // Se o usuário está clicando, não atropela
        if (phase[r.evidence_hash] === 'sending') continue;
        await verifySilent(r);
      }
      setLastPollAt(new Date());
    };
    pollingRef.current = window.setInterval(tick, POLL_INTERVAL_MS);
    return () => {
      if (pollingRef.current) { window.clearInterval(pollingRef.current); pollingRef.current = null; }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows]);

  // Verify silencioso (sem toast) — usado pelo polling.
  async function verifySilent(r: Row) {
    const evHash = r.evidence_hash;
    const stamp = stampOf(r);
    if (!stamp?.ots_base64) return;
    setPhase((p) => ({ ...p, [evHash]: 'processing' }));
    try {
      const { data: v, error } = await supabase.functions.invoke('originstamp-verify', {
        body: { evidence_hash: stamp.merkle_root ?? evHash, ots_base64: stamp.ots_base64 },
      });
      if (error) throw error;
      await persistVerify(r, v);
      if ((v as any)?.confirmed) {
        setPhase((p) => ({ ...p, [evHash]: 'confirmed' }));
        toast.success(`Bloco Bitcoin #${(v as any)?.block_height ?? '?'} confirmado`, {
          description: `Ata "${r.subject || evHash.slice(0, 12)}…" pronta para reabrir.`,
          duration: 12000,
        });
      } else {
        setPhase((p) => ({ ...p, [evHash]: 'processing' }));
      }
    } catch {
      // silencioso: mantém phase anterior
    }
  }

  // Relê o último evento de selo direto do banco e confirma que foi persistido.
  // Retorna o stamp persistido (ou null) e dispara toast com o status real.
  async function confirmPersistedStamp(
    evHash: string,
    opts: { silent?: boolean; expectOts?: boolean; expectConfirmed?: boolean } = {},
  ): Promise<any | null> {
    try {
      const { data, error } = await (supabase.from('forensic_report_stamps') as any)
        .select('payload')
        .eq('evidence_hash', evHash)
        .eq('kind', 'stamp')
        .order('created_at', { ascending: false })
        .limit(1);
      if (error) throw error;
      const persistedStamp = (data as any[])?.[0]?.payload ?? null;
      if (persistedStamp) setStamps((s) => ({ ...s, [evHash]: persistedStamp }));

      if (!opts.silent) {
        if (!persistedStamp || (opts.expectOts && !persistedStamp.ots_base64)) {
          toast.error('Persistência não confirmada', {
            description:
              'O selo não foi encontrado no banco após a atualização. Recarregue a lista — pode ser bloqueio de permissão (RLS) ou sessão expirada.',
          });
        } else if (opts.expectConfirmed && persistedStamp.status !== 'confirmed_bitcoin') {
          toast.info('Selo persistido, aguardando Bitcoin', {
            description: `Status no banco: "${persistedStamp.status ?? 'anchored'}"${
              persistedStamp.bitcoin_block_height ? ` · bloco #${persistedStamp.bitcoin_block_height}` : ''
            }.`,
          });
        } else {
          const label = persistedStamp.bitcoin_block_height
            ? `bloco #${persistedStamp.bitcoin_block_height}`
            : (persistedStamp.status ?? 'anchored');
          toast.success('Persistência confirmada no banco', {
            description: `Selo gravado (${label}).`,
          });
        }
      }
      return persistedStamp;
    } catch (e: any) {
      if (!opts.silent) {
        toast.error('Não foi possível reler o registro', {
          description: e?.message ?? String(e),
        });
      }
      return null;
    }
  }

  async function persistVerify(r: Row, v: any) {
    const stamp = stampOf(r) ?? {};
    const nextStamp = {
      ...stamp,
      ots_base64: v?.upgraded_ots_base64 ?? stamp.ots_base64,
      bitcoin_block_height: v?.block_height ?? stamp.bitcoin_block_height ?? null,
      ots_confirmed_at: v?.confirmed_at ?? stamp.ots_confirmed_at ?? null,
      ots_upgraded_base64: v?.upgraded_ots_base64 ?? stamp.ots_upgraded_base64 ?? null,
      status: v?.confirmed ? 'confirmed_bitcoin' : (stamp.status ?? 'anchored'),
      ots_sha256: v?.ots_sha256 ?? stamp.ots_sha256 ?? null,
      block_hash: v?.block_hash ?? stamp.block_hash ?? null,
      block_merkle_root: v?.block_merkle_root ?? stamp.block_merkle_root ?? null,
      block_time: v?.block_time ?? stamp.block_time ?? null,
      calendars: v?.calendars ?? stamp.calendars,
    };
    await saveStamp(r.evidence_hash, nextStamp);
  }

  async function updateBitcoin(r: Row) {
    const evHash = r.evidence_hash;
    console.log('[RecentNotarialReports] updateBitcoin clicked', { evHash, hasStamp: !!stampOf(r)?.ots_base64 });
    if (!evHash) {
      toast.error('Registro inválido: hash da evidência ausente.');
      return;
    }
    setPhase((p) => ({ ...p, [evHash]: 'sending' }));
    const tId = toast.loading('Consultando OpenTimestamps…');


    try {
      let stamp: any = stampOf(r);

      // FASE A — Anchor: só quando ainda não existe .ots. Persiste imediatamente
      // e encerra. A confirmação Bitcoin leva 1–6h; chamar verify agora só
      // adicionaria latência e uma segunda chance de erro.
      if (!stamp?.ots_base64) {
        toast.loading('Selo ausente — emitindo âncora OpenTimestamps…', { id: tId });
        const { data: anchorData, error: anchorErr } = await supabase.functions.invoke(
          'originstamp-anchor',
          { body: { evidence_hash: evHash, context: { tool: 'ata_notarial', ref_id: evHash } } },
        );
        if (anchorErr) throw anchorErr;
        const os = (anchorData as any)?.originstamp;
        if (!os?.ots_base64) throw new Error('Falha ao emitir selo OTS.');
        const newStamp = {
          merkle_root: evHash,
          ots_base64: os.ots_base64,
          originstamp_id: os.timestamp_id ?? evHash,
          calendar_url: os.calendar_url,
          calendars: os.calendar_url ? [os.calendar_url] : undefined,
          status: 'anchored',
          created_at: os.date_created ?? new Date().toISOString(),
        };
        await saveStamp(evHash, newStamp);
        setPhase((p) => ({ ...p, [evHash]: 'processing' }));
        toast.success('Selo OpenTimestamps emitido', {
          id: tId,
          description:
            'Confirmação Bitcoin leva de 1 a 6 h. Vamos verificar automaticamente a cada 5 min.',
          duration: 8000,
        });
        // Reconfirma no banco que o selo de fato foi gravado.
        await confirmPersistedStamp(evHash, { expectOts: true });
        return;
      }


      // FASE B — Verify: já existe .ots, apenas consulta upgrade.
      setPhase((p) => ({ ...p, [evHash]: 'processing' }));
      toast.loading('Verificando confirmação Bitcoin…', { id: tId });
      const { data: v, error: vErr } = await supabase.functions.invoke('originstamp-verify', {
        body: { evidence_hash: stamp.merkle_root ?? evHash, ots_base64: stamp.ots_base64 },
      });
      if (vErr) throw vErr;

      await persistVerify(r, v);
      const mergedStamp = { ...stamp, ...(v as any) };
      const reopenPayload = reopenPayloadFrom(r, mergedStamp);


      if ((v as any)?.confirmed) {
        setPhase((p) => ({ ...p, [evHash]: 'confirmed' }));
        toast.success(`Bloco Bitcoin #${(v as any)?.block_height ?? '?'} confirmado`, {
          id: tId,
          description: 'Reabra o laudo para baixar o PDF e o .ots atualizados.',
          action: {
            label: 'Reabrir e regerar PDF',
            onClick: () => onReopen(reopenPayload),
          },
          duration: 12000,
        });
      } else {
        setPhase((p) => ({ ...p, [evHash]: 'processing' }));
        toast.info('Ainda sem bloco Bitcoin confirmado', {
          id: tId,
          description: 'A confirmação leva de 1 a 6 h após a selagem. Vamos continuar verificando em segundo plano.',
          duration: 8000,
        });
      }
      // Reconfirma no banco o resultado do verify (confirmado ou ainda ancorado).
      await confirmPersistedStamp(evHash, {
        expectOts: true,
        expectConfirmed: !!(v as any)?.confirmed,
      });
    } catch (e: any) {
      const detail =
        e?.context?.error ??
        e?.context?.body?.error ??
        e?.message ??
        String(e);
      setPhase((p) => ({ ...p, [evHash]: 'failed' }));
      toast.error('Falha ao atualizar ancoragem', {
        id: tId,
        description: typeof detail === 'string' ? detail : JSON.stringify(detail),
      });
    }
  }



  if (loading) {
    return (
      <div className="rounded-lg border bg-muted/20 p-3 text-xs text-muted-foreground flex items-center gap-2">
        <Loader2 className="w-3.5 h-3.5 animate-spin" /> Buscando atas anteriores…
      </div>
    );
  }
  if (!rows || rows.length === 0) return null;

  const pendingCount = (rows ?? []).filter((r) => {
    const s = stampOf(r);
    return s?.ots_base64 && s?.status !== 'confirmed_bitcoin';
  }).length;

  return (
    <div className="mb-4 rounded-lg border bg-muted/10 p-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <History className="w-4 h-4 text-primary" /> Retomar ata notarial anterior
        </div>
        <Button size="sm" variant="ghost" onClick={load} className="h-7 px-2 text-[11px] gap-1">
          <RotateCcw className="w-3 h-3" /> Recarregar
        </Button>
      </div>

      {/* Área de status do polling automático */}
      {pendingCount > 0 && (
        <div className="flex items-center justify-between gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-2 py-1.5 text-[11px]">
          <div className="flex items-center gap-2 text-amber-500">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500" />
            </span>
            <span className="font-medium">
              {pendingCount} ata{pendingCount > 1 ? 's' : ''} aguardando confirmação Bitcoin
            </span>
          </div>
          <span className="text-muted-foreground text-[10px]">
            {lastPollAt
              ? `verificado às ${lastPollAt.toLocaleTimeString('pt-BR')}`
              : 'verificação automática a cada 5 min'}
          </span>
        </div>
      )}

      <p className="text-[11px] text-muted-foreground">
        Atualize a ancoragem Bitcoin (OpenTimestamps) direto na lista ou reabra para baixar o PDF/<code>.ots</code> atualizados.
      </p>
      <div className="space-y-1.5 max-h-72 overflow-auto pr-1">
        {rows.map((r) => {
          const meta = r.metadata ?? {};
          const stamp = stampOf(r);
          const sealed = meta.sealed_stamp ?? null;
          const status = stamp?.status ?? sealed?.status ?? null;
          const block = stamp?.bitcoin_block_height ?? sealed?.bitcoin_block_height ?? null;
          const evHash = r.evidence_hash;
          const alreadyConfirmed = status === 'confirmed_bitcoin' && !!block;
          const rowPhase: Phase =
            phase[evHash] ??
            (alreadyConfirmed
              ? 'confirmed'
              : stamp?.ots_base64
              ? 'processing'
              : 'idle');
          const isBusy = rowPhase === 'sending' || rowPhase === 'processing';

          const phaseChip = (() => {
            switch (rowPhase) {
              case 'sending':
                return { icon: <Send className="w-2.5 h-2.5" />, label: 'Enviando', cls: 'bg-sky-500/15 text-sky-400 border-sky-500/40' };
              case 'processing':
                return { icon: <Loader2 className="w-2.5 h-2.5 animate-spin" />, label: block ? `Bitcoin #${block}` : 'Processando', cls: 'bg-amber-500/15 text-amber-500 border-amber-500/40' };
              case 'confirmed':
                return { icon: <CheckCircle2 className="w-2.5 h-2.5" />, label: `Bitcoin #${block ?? '?'}`, cls: 'bg-emerald-500/15 text-emerald-500 border-emerald-500/40' };
              case 'failed':
                return { icon: <AlertTriangle className="w-2.5 h-2.5" />, label: 'Falhou', cls: 'bg-red-500/15 text-red-500 border-red-500/40' };
              default:
                return { icon: null, label: 'Sem selo', cls: 'bg-slate-500/15 text-slate-400 border-slate-500/40' };
            }
          })();

          return (
            <div key={evHash} className="flex flex-wrap items-center gap-2 rounded-md border bg-background p-2">
              <FileSignature className="w-3.5 h-3.5 text-amber-500 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-[11px] font-medium truncate">
                  {r.subject || evHash.slice(0, 12) + '…'}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  {new Date(r.created_at).toLocaleString('pt-BR')} · <code className="font-mono">{evHash.slice(0, 10)}…</code>
                </div>
              </div>
              <Badge variant="outline" className={`text-[9px] gap-1 ${phaseChip.cls}`}>
                {phaseChip.icon}
                {phaseChip.label}
              </Badge>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 px-2 text-[11px] gap-1"
                disabled={rowPhase === 'sending' || alreadyConfirmed}
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); void updateBitcoin(r); }}
                title={alreadyConfirmed ? 'Bloco já confirmado' : 'Atualizar ancoragem Bitcoin agora'}
              >
                {isBusy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Bitcoin className="w-3 h-3" />}
                {alreadyConfirmed ? 'Confirmado' : rowPhase === 'sending' ? 'Enviando…' : rowPhase === 'processing' ? 'Verificar agora' : 'Atualizar Bitcoin'}
              </Button>
              {hasFullPayload(r) ? (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="h-7 px-2 text-[11px]"
                  disabled={reopening === evHash}
                  onClick={(e) => { e.preventDefault(); e.stopPropagation(); void handleReopen(r); }}
                >
                  {reopening === evHash ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Reabrir'}
                </Button>
              ) : (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="h-7 px-2 text-[11px] gap-1"
                  title="Esta ata foi emitida antes da persistência do laudo completo; é possível emitir a Certidão de Ancoragem."
                  onClick={(e) => { e.preventDefault(); e.stopPropagation(); void handleCertidao(r); }}
                >
                  <FileDown className="w-3 h-3" /> Certidão
                </Button>
              )}

            </div>
          );
        })}
      </div>
    </div>
  );
}



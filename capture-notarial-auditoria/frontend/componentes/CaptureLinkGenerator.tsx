import { useState, useRef, useEffect } from "react";
import { StjComplianceBanner } from '@/components/juridico/StjComplianceBanner';
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  Link2,
  Copy,
  Trash2,
  Loader2,
  QrCode,
  ExternalLink,
  RefreshCcw,
  ShieldCheck,
  Clock,
  FileText,
  Smartphone,
  ShieldAlert,
  AlertTriangle,
  Download,
  Info,
  Video,
  File,
  Music,
  Image as ImageIcon,
  Archive,
} from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useAuth } from "@/hooks/useAuth";
import { gerarLaudoCaptureLinkPDF } from "@/lib/capture-link-pdf";
import { useForensicAuthor } from "@/hooks/useForensicAuthor";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface Evidence {
  id: string;
  file_name: string;
  file_path: string;
  file_size: number;
  mime_type: string;
  hash_client: string;
  captured_at_client: string;
  created_at: string;
  metadata?: any;
}

interface Session {
  id: string;
  token: string;
  status: "waiting" | "active" | "completed" | "expired";
  expires_at: string;
  created_at: string;
}

export default function CaptureLinkGenerator() {
  const { user } = useAuth();
  const { author } = useForensicAuthor();
  const [duration, setDuration] = useState("60");
  const [generating, setGenerating] = useState(false);
  const [lastSession, setLastSession] = useState<Session | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [exportingId, setExportingId] = useState<string | null>(null);
  const [upgradingId, setUpgradingId] = useState<string | null>(null);
  const [sessionEvidence, setSessionEvidence] = useState<Record<string, Evidence[]>>({});
  const [aiAlerts, setAiAlerts] = useState<Record<string, boolean>>({});

  const fetchSessions = async () => {
    if (!user) return;
    const { data, error } = await supabase
      .from("capture_link_sessions")
      .select("*")
      .eq("operator_id", user.id)
      .order("created_at", { ascending: false })
      .limit(10);

    if (error) {
      console.error("Fetch sessions error:", error);
    } else {
      const sess = (data as Session[]) || [];
      setSessions(sess);

      // Fetch evidence for each session
      if (sess.length > 0) {
        const sessionIds = sess.map((s) => s.id);
        const { data: evData } = await supabase.from("capture_link_evidence").select("*").in("session_id", sessionIds);

        const evMap: Record<string, Evidence[]> = {};
        evData?.forEach((e: any) => {
          if (!evMap[e.session_id]) evMap[e.session_id] = [];
          evMap[e.session_id].push(e);
        });
        setSessionEvidence(evMap);

        // Check for AI alerts in evidence
        const aiSess: Record<string, boolean> = {};
        evData?.forEach((e: any) => {
          if (
            e.metadata?.ai_detection?.veredicto?.toUpperCase().includes("IA") &&
            e.metadata?.ai_detection?.pontuacao > 60
          ) {
            aiSess[e.session_id] = true;
          }
        });
        setAiAlerts(aiSess);
      }
    }
    setLoadingSessions(false);
  };

  useEffect(() => {
    fetchSessions();

    // Auto-refresh every 5 seconds to get new evidence without clicking refresh
    const refreshInterval = setInterval(() => {
      fetchSessions();
    }, 5000);

    // Realtime subscription for sessions
    const channel = supabase
      .channel("capture_link_updates")
      .on(
        "postgres_changes",
        {
          event: "*",
          schema: "public",
          table: "capture_link_sessions",
          filter: `operator_id=eq.${user?.id}`,
        },
        () => {
          fetchSessions();
        },
      )
      .subscribe();

    return () => {
      clearInterval(refreshInterval);
      supabase.removeChannel(channel);
    };
  }, [user]);

  const generateLink = async () => {
    if (!user) return;
    setGenerating(false);
    setGenerating(true);
    try {
      const token = Math.random().toString(36).substring(2, 8) + Math.random().toString(36).substring(2, 8);
      const expiresAt = new Date(Date.now() + parseInt(duration) * 60000).toISOString();

      const { data, error } = await supabase
        .from("capture_link_sessions")
        .insert({
          token,
          expires_at: expiresAt,
          operator_id: user.id,
          status: "waiting",
        })
        .select()
        .single();

      if (error) throw error;
      setLastSession(data as Session);
      toast.success("Link de captura gerado com sucesso!");
    } catch (e: any) {
      console.error("Generate link error:", e);
      toast.error("Erro ao gerar link: " + e.message);
    } finally {
      setGenerating(false);
    }
  };

  const copyLink = (token: string) => {
    const url = `${window.location.origin}/capture-link/${token}`;
    navigator.clipboard.writeText(url);
    toast.success("Link copiado para a área de transferência!");
  };

  const ensureTimestampProofsForExport = async (sessionId: string, evidence: Evidence[]) => {
    const timestampProofs: Record<string, any> = {};

    for (const ev of evidence) {
      let { data: proof } = await supabase
        .from("capture_link_timestamp_proofs")
        .select("*")
        .eq("session_id", sessionId)
        .eq("file_path", ev.file_path)
        .maybeSingle();
      let proofRecord: any = proof;

      const needsAnchor = !proofRecord || !proofRecord.ots_base64 || !proofRecord.tsr_base64;
      if (needsAnchor) {
        const { data: anchorData, error: anchorError } = await supabase.functions.invoke("originstamp-anchor", {
          body: { evidence_hash: ev.hash_client, context: { tool: "capture_link", ref_id: ev.hash_client } },
        });

        if (!anchorError && (anchorData?.originstamp?.ots_base64 || anchorData?.rfc3161?.token_base64)) {
          const payload: any = {
            session_id: sessionId,
            evidence_id: ev.id,
            file_path: ev.file_path,
            hash_sha256: ev.hash_client,
            ots_base64: proofRecord?.ots_base64 ?? anchorData?.originstamp?.ots_base64 ?? anchorData?.originstamp?.raw_response_base64 ?? null,
            tsr_base64: proofRecord?.tsr_base64 ?? anchorData?.rfc3161?.token_base64 ?? null,
            submitted_at: anchorData?.submitted_at ?? proofRecord?.submitted_at ?? ev.created_at,
            status: proofRecord?.status === "confirmed_bitcoin" ? "confirmed_bitcoin" : "anchored",
          };

          if (proofRecord?.id) {
            const { data: updatedProof, error: updateProofError } = await supabase
              .from("capture_link_timestamp_proofs")
              .update(payload)
              .eq("id", proofRecord.id)
              .select("*")
              .maybeSingle();
            if (updateProofError) throw updateProofError;
            proofRecord = updatedProof ?? { ...proofRecord, ...payload };
          } else {
            const { data: createdProof, error: createProofError } = await supabase
              .from("capture_link_timestamp_proofs")
              .insert(payload)
              .select("*")
              .maybeSingle();
            if (createProofError) throw createProofError;
            proofRecord = createdProof ?? payload;
          }
        }
      }

      if (proofRecord?.id && proofRecord?.ots_base64 && proofRecord.status !== "confirmed_bitcoin") {
        const { data: verifyData, error: verifyError } = await supabase.functions.invoke("originstamp-verify", {
          body: {
            evidence_hash: proofRecord.hash_sha256 || ev.hash_client,
            ots_base64: proofRecord.ots_base64,
          },
        });

        if (!verifyError && verifyData?.confirmed) {
          const confirmedAt = verifyData.confirmed_at ?? new Date().toISOString();
          const blockHeight = verifyData.block_height ?? verifyData.checks?.find((check: any) => check?.block_height)?.block_height ?? null;
          const txid = verifyData.txid ?? verifyData.checks?.find((check: any) => check?.txid)?.txid ?? proofRecord.blockchain_txid ?? null;
          const explorerUrl = txid
            ? `https://mempool.space/tx/${txid}`
            : blockHeight
              ? `https://mempool.space/block/${blockHeight}`
              : proofRecord.explorer_url ?? null;
          const confirmationPayload: Record<string, any> = {
            status: "confirmed_bitcoin",
            verified_at: confirmedAt,
            ots_confirmed_at: confirmedAt,
            ots_base64: verifyData.upgraded_ots_base64 ?? proofRecord.ots_base64,
            bitcoin_block_height: blockHeight,
            ...(txid ? { blockchain_txid: txid } : {}),
            ...(explorerUrl ? { explorer_url: explorerUrl } : {}),
            ...(verifyData.ots_sha256 ? { ots_sha256: verifyData.ots_sha256 } : {}),
            ...(verifyData.block_hash ? { block_hash: verifyData.block_hash } : {}),
            ...(verifyData.block_merkle_root ? { block_merkle_root: verifyData.block_merkle_root } : {}),
            ...(verifyData.block_time ? { block_time: verifyData.block_time } : {}),
          };

          const { data: confirmedProof, error: confirmError } = await supabase
            .from("capture_link_timestamp_proofs")
            // @ts-ignore migration: strict-mode wave
            .update(confirmationPayload)
            .eq("id", proofRecord.id)
            .select("*")
            .maybeSingle();
          if (confirmError) throw confirmError;
          proofRecord = confirmedProof ?? { ...proofRecord, ...confirmationPayload };
        } else if (!verifyError && verifyData?.upgraded_ots_base64 && verifyData.upgraded_ots_base64 !== proofRecord.ots_base64) {
          const { data: upgradedProof, error: upgradeError } = await supabase
            .from("capture_link_timestamp_proofs")
            .update({ ots_base64: verifyData.upgraded_ots_base64 })
            .eq("id", proofRecord.id)
            .select("*")
            .maybeSingle();
          if (upgradeError) throw upgradeError;
          proofRecord = upgradedProof ?? { ...proofRecord, ots_base64: verifyData.upgraded_ots_base64 };
        }
      }

      if (proofRecord) timestampProofs[ev.file_path] = proofRecord;
    }

    return timestampProofs;
  };

  const exportPDF = async (s: Session) => {
    setExportingId(s.id);
    try {
      // 1. Fetch evidence
      const { data: evidence, error } = await supabase.from("capture_link_evidence").select("*").eq("session_id", s.id);

      if (error) throw error;

      // 2. Fetch Audit Logs for this session
      const { data: auditLogs } = await supabase
        .from("audit_logs")
        .select("*")
        .eq("entity_id", s.id)
        .order("created_at", { ascending: true });

      // 3. Garantir selo RFC 3161/OTS antes de montar o PDF.
      const timestampProofs = await ensureTimestampProofsForExport(s.id, (evidence as Evidence[]) || []);

      // IP do operador: tenta audit_log primeiro, depois consulta provedores públicos
      // como fallback (alguns ad-blockers bloqueiam ipify).
      let operatorIp: string | null =
        (auditLogs || []).find((l: any) => l.ip_address)?.ip_address ?? null;

      if (!operatorIp) {
        const providers = [
          'https://api.ipify.org?format=json',
          'https://ipapi.co/json/',
          'https://ifconfig.co/json',
        ];
        for (const url of providers) {
          try {
            const r = await fetch(url, { signal: AbortSignal.timeout(2500) });
            if (!r.ok) continue;
            const j = await r.json();
            operatorIp = j.ip || j.query || null;
            if (operatorIp) break;
          } catch { /* try next */ }
        }
      }


      // Gera signed URLs (7 dias) para cada evidência, já que o bucket é privado
      const evidenceWithUrls = await Promise.all(
        ((evidence as any[]) || []).map(async (ev) => {
          try {
            const { data: signed } = await supabase
              .storage
              .from("evidence_vault")
              .createSignedUrl(ev.file_path, 60 * 60 * 24 * 7);
            return { ...ev, signed_url: signed?.signedUrl || null };
          } catch {
            return { ...ev, signed_url: null };
          }
        }),
      );

      await gerarLaudoCaptureLinkPDF({
        id: s.id,
        token: s.token,
        operator_name: user?.user_metadata?.full_name || "Operador",
        operator_id: user?.id,
        operator_ip: operatorIp,
        created_at: s.created_at,
        expires_at: s.expires_at,
        evidence: evidenceWithUrls as any,
        author: author,
        audit_logs: auditLogs || [],
        timestamp_proofs: timestampProofs,
      });

      toast.success("Laudo PDF gerado com sucesso!");
    } catch (e: any) {
      toast.error("Erro ao exportar PDF: " + e.message);
    } finally {
      setExportingId(null);
    }
  };

  const downloadFile = async (filePath: string, fileName: string) => {
    try {
      const { data, error } = await supabase.storage.from("evidence_vault").download(filePath);

      if (error) throw error;

      const url = window.URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (e: any) {
      toast.error("Erro ao baixar arquivo: " + e.message);
    }
  };

  const upgradeTimestamps = async (sessionId: string) => {
    setUpgradingId(sessionId);
    try {
      const evidence = sessionEvidence[sessionId] || [];
      if (evidence.length === 0) {
        toast.error("Nenhuma evidência encontrada para atualizar.");
        return;
      }

      toast.loading("Consultando calendários Bitcoin (OpenTimestamps)...", { id: "upgrade-ots" });

      let updatedCount = 0;
      let anchoredCount = 0;
      let createdNowCount = 0;
      for (const ev of evidence) {
        let { data: existingProof } = await supabase
          .from("capture_link_timestamp_proofs")
          .select("id, hash_sha256, ots_base64, tsr_base64, status, submitted_at, blockchain_txid, explorer_url, bitcoin_block_height, ots_confirmed_at, verified_at, ots_sha256, block_hash, block_merkle_root, block_time")
          .eq("session_id", sessionId)
          .eq("file_path", ev.file_path)
          .maybeSingle();

        // Re-ancora se faltar OTS ou TSR (RFC 3161). FreeTSA pode ter falhado
        // na captura original — neste caso emitimos o selo RFC 3161 agora.
        const needsAnchor = !existingProof || !existingProof.ots_base64 || !existingProof.tsr_base64;
        if (needsAnchor) {
          const { data: anchorData, error: anchorError } = await supabase.functions.invoke("originstamp-anchor", {
            body: { evidence_hash: ev.hash_client, context: { tool: "capture_link", ref_id: ev.hash_client } },
          });

          if (anchorError || !anchorData?.originstamp) {
            console.error(`Erro ao ancorar hash ${ev.hash_client}:`, anchorError);
            continue;
          }

          const otsBase64 = existingProof?.ots_base64
            ?? anchorData.originstamp.ots_base64
            ?? anchorData.originstamp.raw_response_base64
            ?? null;
          const newTsr = anchorData.rfc3161?.token_base64 ?? null;
          const tsrBase64 = existingProof?.tsr_base64 ?? newTsr;
          const tsrAdded = !existingProof?.tsr_base64 && !!newTsr;

          if (!existingProof) {
            const { data: createdProof, error: createProofError } = await supabase
              .from("capture_link_timestamp_proofs")
              .insert({
                session_id: sessionId,
                evidence_id: ev.id,
                file_path: ev.file_path,
                hash_sha256: ev.hash_client,
                ots_base64: otsBase64,
                tsr_base64: tsrBase64,
                submitted_at: anchorData.submitted_at ?? ev.created_at,
                status: "anchored",
              })
              .select("id, hash_sha256, ots_base64, tsr_base64, status, submitted_at, blockchain_txid, explorer_url, bitcoin_block_height, ots_confirmed_at, verified_at, ots_sha256, block_hash, block_merkle_root, block_time")
              .maybeSingle();
            if (createProofError) {
              console.error(`Erro ao salvar selo temporal ${ev.hash_client}:`, createProofError);
              continue;
            }
            existingProof = createdProof ?? null;
            if (tsrBase64 || otsBase64) {
              anchoredCount++;
              createdNowCount++;
            }
          } else {
            const { error: updateAnchorError } = await supabase
              .from("capture_link_timestamp_proofs")
              .update({
                ots_base64: otsBase64,
                tsr_base64: tsrBase64,
                submitted_at: anchorData.submitted_at ?? existingProof.submitted_at,
                status: existingProof.status === "confirmed_bitcoin" ? existingProof.status : "anchored",
              })
              .eq("id", existingProof.id);
            if (updateAnchorError) {
              console.error(`Erro ao atualizar selo temporal ${ev.hash_client}:`, updateAnchorError);
              continue;
            }
            existingProof = { ...existingProof, ots_base64: otsBase64, tsr_base64: tsrBase64 };
            if (tsrAdded) anchoredCount++;
          }
        }

        if (!existingProof?.id) {
          console.error(`Selo temporal não persistido para ${ev.hash_client}; atualização Bitcoin ignorada.`);
          continue;
        }

        const wasConfirmed = existingProof?.status === "confirmed_bitcoin";
        const previousOts = existingProof?.ots_base64 ?? null;
        const previousBlock = existingProof?.bitcoin_block_height ?? null;

        const { data, error } = await supabase.functions.invoke("originstamp-verify", {
          body: {
            evidence_hash: existingProof?.hash_sha256 || ev.hash_client,
            ots_base64: existingProof?.ots_base64 ?? undefined,
          },
        });

        if (error) {
          console.error(`Erro ao verificar hash ${ev.hash_client}:`, error);
          continue;
        }

        if (data?.confirmed) {
          const confirmedAt = data.confirmed_at ?? new Date().toISOString();
          const blockHeight = data.block_height ?? data.checks?.find((check: any) => check?.block_height)?.block_height ?? null;
          const txid = data.txid ?? data.checks?.find((check: any) => check?.txid)?.txid ?? existingProof?.blockchain_txid ?? null;
          const explorerUrl = txid
            ? `https://mempool.space/tx/${txid}`
            : blockHeight
              ? `https://mempool.space/block/${blockHeight}`
              : existingProof?.explorer_url ?? null;

          const { error: updateError } = await supabase
            .from("capture_link_timestamp_proofs")
            .update({
              status: "confirmed_bitcoin",
              verified_at: confirmedAt,
              ots_confirmed_at: confirmedAt,
              ots_base64: data.upgraded_ots_base64 ?? existingProof?.ots_base64 ?? null,
              bitcoin_block_height: blockHeight,
              ...(txid ? { blockchain_txid: txid } : {}),
              ...(explorerUrl ? { explorer_url: explorerUrl } : {}),
              ...(data.ots_sha256 ? { ots_sha256: data.ots_sha256 } : {}),
              ...(data.block_hash ? { block_hash: data.block_hash } : {}),
              ...(data.block_merkle_root ? { block_merkle_root: data.block_merkle_root } : {}),
              ...(data.block_time ? { block_time: data.block_time } : {}),
            } as any)
            .eq("session_id", sessionId)
            .eq("file_path", ev.file_path);

          if (updateError) {
            console.error(`Erro ao persistir confirmação Bitcoin ${ev.hash_client}:`, updateError);
          } else {
            const upgradedChanged = !!data.upgraded_ots_base64 && data.upgraded_ots_base64 !== previousOts;
            const blockAdded = !!blockHeight && blockHeight !== previousBlock;
            if (!wasConfirmed || upgradedChanged || blockAdded) updatedCount++;
          }
        } else if (data?.upgraded_ots_base64) {
          const upgradedChanged = data.upgraded_ots_base64 !== previousOts;
          const { error: updateOtsError } = await supabase
            .from("capture_link_timestamp_proofs")
            .update({ ots_base64: data.upgraded_ots_base64 })
            .eq("session_id", sessionId)
            .eq("file_path", ev.file_path);
          if (updateOtsError) console.error(`Erro ao persistir .ots atualizado ${ev.hash_client}:`, updateOtsError);
          else if (upgradedChanged) anchoredCount++;
        }
      }

      if (updatedCount > 0) {
        toast.success(`${updatedCount} selo${updatedCount > 1 ? "s" : ""} Bitcoin confirmado${updatedCount > 1 ? "s" : ""} com sucesso!`, { id: "upgrade-ots" });
        fetchSessions(); // Recarregar para garantir dados novos no laudo
      } else if (anchoredCount > 0) {
        const createdNow = createdNowCount > 0
          ? ` ${createdNowCount} selo${createdNowCount > 1 ? "s" : ""} foi${createdNowCount > 1 ? "ram" : ""} criado${createdNowCount > 1 ? "s" : ""} agora; a confirmação Bitcoin passa a contar desta emissão.`
          : "";
        toast.info(`${anchoredCount} selo${anchoredCount > 1 ? "s" : ""} atualizado${anchoredCount > 1 ? "s" : ""}; Bitcoin ainda sem confirmação detectada.${createdNow}`, { id: "upgrade-ots" });
      } else {
        toast.info("Nenhuma nova confirmação Bitcoin encontrada no .ots já emitido.", { id: "upgrade-ots" });
      }
    } catch (e: any) {
      toast.error("Erro ao atualizar selos: " + e.message, { id: "upgrade-ots" });
    } finally {
      setUpgradingId(null);
    }
  };

  const exportEvidenceZip = async (s: Session) => {
    toast.loading("Preparando pacote de evidência lacrada...", { id: "zip-export" });
    try {
      const { data: evidence, error } = await supabase.from("capture_link_evidence").select("*").eq("session_id", s.id);

      if (error) throw error;
      if (!evidence || evidence.length === 0) {
        toast.error("Nenhum arquivo para exportar", { id: "zip-export" });
        return;
      }

      const JSZip = (await import("jszip")).default;
      const zip = new JSZip();

      const folder = zip.folder(`evidencia_lacrada_${s.token}`);
      const filesFolder = folder?.folder("arquivos_originais");
      const metaFolder = folder?.folder("metadados_forenses");

      let chainOfCustody = `CADEIA DE CUSTÓDIA - TRACE HUB CAPTURE LINK\n`;
      chainOfCustody += `==========================================\n\n`;
      chainOfCustody += `ID SESSÃO: ${s.id}\n`;
      chainOfCustody += `OPERADOR: ${user?.user_metadata?.full_name || user?.email}\n`;
      chainOfCustody += `CRIADO EM: ${new Date(s.created_at).toLocaleString()}\n\n`;
      chainOfCustody += `ARQUIVOS COLETADOS:\n`;

      // Helper para decodificar base64 (.ots/.tsr) em Uint8Array para o ZIP
      const b64ToBytes = (b64: string): Uint8Array => {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
      };

      // Busca selos temporais (.ots OpenTimestamps + .tsr RFC 3161) gerados para esta sessão
      const { data: proofs } = await supabase
        .from("capture_link_timestamp_proofs")
        .select("file_path, hash_sha256, ots_base64, tsr_base64, status, submitted_at, blockchain_txid, explorer_url, bitcoin_block_height, ots_confirmed_at, verified_at, ots_sha256, block_hash, block_merkle_root, block_time")
        .eq("session_id", s.id);
      const proofsByPath = new Map<string, any>();
      (proofs || []).forEach((p: any) => proofsByPath.set(p.file_path, p));
      let otsCount = 0;
      let tsrCount = 0;

      for (const ev of evidence) {
        // Baixar arquivo original
        const { data: fileBlob } = await supabase.storage.from("evidence_vault").download(ev.file_path);

        if (fileBlob) {
          filesFolder?.file(ev.file_name, fileBlob);

          // Gerar arquivos de hash independentes
          metaFolder?.file(`${ev.file_name}.sha256.txt`, ev.hash_client);
          if ((ev as any).hash_client_sha512) {
            metaFolder?.file(`${ev.file_name}.sha512.txt`, (ev as any).hash_client_sha512);
          }

          // Selos temporais — tenta DB primeiro; se ausentes, ancora agora
          // (mesma estratégia da Ata Notarial Digital, que sempre gera no ato)
          let proof: any = proofsByPath.get(ev.file_path);
          if (!proof?.ots_base64 || !proof?.tsr_base64) {
            try {
              const { data: anchorData } = await supabase.functions.invoke("originstamp-anchor", {
                body: { evidence_hash: ev.hash_client, context: { tool: "capture_link", ref_id: ev.hash_client } },
              });
              if (anchorData?.originstamp || anchorData?.rfc3161) {
                const otsB64 = proof?.ots_base64
                  ?? anchorData?.originstamp?.ots_base64
                  ?? anchorData?.originstamp?.raw_response_base64
                  ?? null;
                const tsrB64 = proof?.tsr_base64 ?? anchorData?.rfc3161?.token_base64 ?? null;
                const preservedStatus = proof?.status === "confirmed_bitcoin" ? proof.status : "anchored";
                proof = { ...(proof || {}), ots_base64: otsB64, tsr_base64: tsrB64, status: preservedStatus, submitted_at: proof?.submitted_at ?? anchorData?.submitted_at ?? new Date().toISOString() };
                // Persiste para reaproveitar em downloads futuros (best-effort)
                try {
                  await supabase.from("capture_link_timestamp_proofs").upsert({
                    session_id: s.id,
                    evidence_id: ev.id,
                    file_path: ev.file_path,
                    hash_sha256: ev.hash_client,
                    ots_base64: otsB64,
                    tsr_base64: tsrB64,
                    submitted_at: proof.submitted_at,
                    status: preservedStatus,
                  }, { onConflict: "evidence_id" });
                } catch (persistErr) { console.warn("[capture-link] falha ao persistir selo", persistErr); }
              }
            } catch (anchorErr) {
              console.warn("[capture-link] falha ao ancorar no ato do download", anchorErr);
            }
          }

          if (proof?.ots_base64) {
            try {
              metaFolder?.file(`${ev.file_name}.ots`, b64ToBytes(proof.ots_base64));
              otsCount++;
            } catch (e) { console.warn("Falha ao anexar .ots", e); }
          }
          if (proof?.tsr_base64) {
            try {
              metaFolder?.file(`${ev.file_name}.tsr`, b64ToBytes(proof.tsr_base64));
              tsrCount++;
            } catch (e) { console.warn("Falha ao anexar .tsr", e); }
          }

          // JSON de metadados individuais
          metaFolder?.file(
            `${ev.file_name}.metadata.json`,
            JSON.stringify(
              {
                ...ev,
                timestamp_proof: proof ? {
                  status: proof.status,
                  submitted_at: proof.submitted_at,
                  has_ots: !!proof.ots_base64,
                  has_tsr: !!proof.tsr_base64,
                } : null,
                security_notice: "Este JSON contém os metadados brutos capturados no dispositivo da vítima.",
              },
              null,
              2,
            ),
          );

          chainOfCustody += `- ${ev.file_name}\n`;
          chainOfCustody += `  SHA-256: ${ev.hash_client}\n`;
          chainOfCustody += `  SHA-512: ${(ev as any).hash_client_sha512 || "N/A"}\n`;
          chainOfCustody += `  DATA: ${new Date(ev.captured_at_client).toLocaleString()}\n`;
          chainOfCustody += `  .ots (OpenTimestamps/Bitcoin): ${proof?.ots_base64 ? "SIM" : "NÃO"}\n`;
          chainOfCustody += `  .tsr (RFC 3161/FreeTSA): ${proof?.tsr_base64 ? "SIM" : "NÃO"}\n\n`;
        }
      }


      if (otsCount === 0 && tsrCount === 0) {
        chainOfCustody += `\nAVISO: Nenhum selo temporal (.ots/.tsr) encontrado para esta sessão.\n`;
        chainOfCustody += `Use o botão "Atualizar selos Bitcoin" no painel para ancorar e re-gerar o pacote.\n`;
      }

      folder?.file("cadeia-custodia.txt", chainOfCustody);
      folder?.file(
        "LEIA-ME.txt",
        "PACOTE DE EVIDÊNCIA LACRADA (ISO 27037)\n\n" +
          "Este pacote contém os arquivos originais coletados sem qualquer alteração,\n" +
          "acompanhados de seus respectivos hashes de integridade e metadados forenses.\n\n" +
          "VALIDADE JURÍDICA E CADEIA DE CUSTÓDIA:\n" +
          "O material aqui contido deve ser acompanhado do 'Relatório de Sessão de Captura' (PDF)\n" +
          "e, para fins judiciais, deve ser juntado aos autos mediante Termo de Arrecadação que\n" +
          "referencie o ID de Sessão: " +
          s.id +
          ".\n\n" +
          "Instruções para o Perito:\n" +
          "1. Verifique a integridade dos arquivos na pasta 'arquivos_originais' confrontando\n" +
          "   com os hashes contidos na pasta 'metadados_forenses' ou no arquivo 'cadeia-custodia.txt'.\n" +
          "2. O hash SHA-256 deve ser calculado sobre o binário bruto do arquivo.\n" +
          "3. Verifique a ancoragem Bitcoin/OpenTimestamps no relatório PDF usando o bloco/prova .ots informados.\n" +
          "4. Qualquer divergência indica que a integridade foi comprometida após a arrecadação.",
      );

      const content = await zip.generateAsync({ type: "blob" });
      const url = window.URL.createObjectURL(content);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `evidencia_lacrada_${s.token}.zip`);
      document.body.appendChild(link);
      link.click();
      link.remove();

      toast.success("Pacote de evidência lacrada gerado!", { id: "zip-export" });
    } catch (e: any) {
      toast.error("Erro ao gerar pacote ZIP: " + e.message, { id: "zip-export" });
    }
  };

  const getFileIcon = (mimeType: string) => {
    if (mimeType.startsWith("image/")) return <ImageIcon className="w-3 h-3" />;
    if (mimeType.startsWith("video/")) return <Video className="w-3 h-3" />;
    if (mimeType.startsWith("audio/")) return <Music className="w-3 h-3" />;
    return <File className="w-3 h-3" />;
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "waiting":
        return (
          <Badge variant="outline" className="text-amber-500 border-amber-500/30 bg-amber-500/5">
            Aguardando
          </Badge>
        );
      case "active":
        return (
          <Badge variant="outline" className="text-emerald-500 border-emerald-500/30 bg-emerald-500/5 animate-pulse">
            Ativa
          </Badge>
        );
      case "completed":
        return (
          <Badge variant="outline" className="text-blue-500 border-blue-500/30 bg-blue-500/5">
            Concluída
          </Badge>
        );
      case "expired":
        return (
          <Badge variant="outline" className="text-muted-foreground border-border bg-muted/50">
            Expirada
          </Badge>
        );
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="space-y-4 min-w-0 max-w-full">
      <StjComplianceBanner variant="collection" customMessage="Link gerado para que a vítima ou testemunha envie a evidência a partir do próprio dispositivo. Hash SHA-256 calculado na origem, antes do upload. Selo temporal e cadeia Merkle aplicados no lote." />
      <div className="grid lg:grid-cols-2 gap-6 min-w-0 max-w-full">
      <div className="space-y-6 min-w-0">
        <Card className="border-primary/20 bg-primary/5 min-w-0 max-w-full overflow-hidden">
          <CardHeader className="p-4 sm:p-6">
            <CardTitle className="flex items-center gap-2 text-primary text-lg sm:text-2xl break-words">
              <Link2 className="w-5 h-5 shrink-0" />
              Capture Link
            </CardTitle>
            <CardDescription>Coleta de provas em 3 passos simples.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6 p-4 sm:p-6 pt-0 sm:pt-0">
            <div className="space-y-4">
              <div className="relative">
                <div className="flex items-center gap-3 sm:gap-4 mb-6">
                  <div
                    className={cn(
                      "w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm border-2 transition-all shrink-0",
                      !lastSession
                        ? "bg-primary border-primary text-primary-foreground shadow-lg shadow-primary/20 scale-110"
                        : "bg-muted border-muted text-muted-foreground",
                    )}
                  >
                    1
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-bold">Configure a Duração</p>
                    <p className="text-[10px] text-muted-foreground">Quanto tempo o link ficará ativo</p>
                  </div>
                </div>

                <Select value={duration} onValueChange={setDuration}>
                  <SelectTrigger className="bg-background border-primary/20 h-12 w-full">
                    <SelectValue placeholder="Selecione o tempo" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="30">30 minutos (Emergencial)</SelectItem>
                    <SelectItem value="60">1 hora (Padrão Forense)</SelectItem>
                    <SelectItem value="1440">24 horas (Preservação Longa)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Button
                onClick={generateLink}
                disabled={generating}
                className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-black h-14 text-sm sm:text-lg shadow-xl shadow-primary/20 group overflow-hidden relative px-3"
              >
                <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000" />
                {generating ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <span className="flex items-center justify-center gap-2 whitespace-nowrap">
                    <QrCode className="w-5 h-5 shrink-0" />
                    <span className="truncate">GERAR QR CODE</span>
                  </span>
                )}
              </Button>
            </div>

            {lastSession && (
              <div className="p-4 sm:p-6 bg-background rounded-2xl border-2 border-primary/30 shadow-2xl space-y-6 animate-in fade-in zoom-in duration-500 relative overflow-hidden max-w-full">
                <div className="absolute top-2 right-2">
                  <Badge
                    variant="secondary"
                    className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 text-[10px] animate-pulse"
                  >
                    Link Ativo
                  </Badge>
                </div>

                <div className="flex items-center gap-4 pt-6 sm:pt-0">
                  <div className="w-8 h-8 rounded-full bg-primary border-primary text-primary-foreground flex items-center justify-center font-bold text-sm shadow-lg shadow-primary/20 scale-110 border-2 shrink-0">
                    2
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-bold">Compartilhe com a Vítima</p>
                    <p className="text-[10px] text-muted-foreground">Mostre o QR Code ou envie o link</p>
                  </div>
                </div>

                <div className="flex justify-center bg-white p-3 sm:p-6 rounded-2xl shadow-inner border-2 sm:border-4 border-slate-50 relative group max-w-full overflow-hidden">
                  <div className="w-full max-w-[220px] aspect-square">
                    <QRCodeSVG
                      value={`${window.location.origin}/capture-link/${lastSession.token}`}
                      level="H"
                      includeMargin={true}
                      className="w-full h-full"
                    />
                  </div>
                  <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center pointer-events-none">
                    <Smartphone className="w-12 h-12 text-primary/20 animate-bounce" />
                  </div>
                </div>

                <div className="space-y-3">
                  <Label className="text-[10px] uppercase font-black tracking-widest opacity-40">
                    Link Direto para Enviar
                  </Label>
                  <div className="flex gap-2">
                    <div className="relative flex-1 min-w-0">
                      <Input
                        value={`${window.location.origin}/capture-link/${lastSession.token}`}
                        readOnly
                        className="pr-10 bg-muted/30 border-primary/20 font-mono text-xs h-11 truncate"
                      />
                      <Link2 className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 opacity-30" />
                    </div>
                    <Button
                      size="icon"
                      onClick={() => copyLink(lastSession.token)}
                      className="shrink-0 h-11 w-11 shadow-lg shadow-primary/10"
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                  <div className="flex items-center justify-center gap-2 py-1 px-3 bg-primary/5 rounded-full w-fit mx-auto border border-primary/10">
                    <Clock className="w-3 h-3 text-primary" />
                    <p className="text-[10px] text-primary font-black uppercase tracking-tighter">
                      Expira em {new Date(lastSession.expires_at).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="border-dashed border-border/60 bg-muted/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-bold flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              Padrão ISO 27037
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-[11px] text-muted-foreground leading-snug">
              <li className="flex gap-2">
                <span className="text-emerald-500 font-bold">✓</span>
                <span>Hashes gerados no dispositivo de origem (vítima) via Web Crypto API.</span>
              </li>
              <li className="flex gap-2">
                <span className="text-emerald-500 font-bold">✓</span>
                <span>Registro imutável de IP, User-Agent e Modelo do Dispositivo.</span>
              </li>
              <li className="flex gap-2">
                <span className="text-emerald-500 font-bold">✓</span>
                <span>Timestamp selado e conferência de integridade Servidor-Cliente.</span>
              </li>
            </ul>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-6 min-w-0">
        <Card className="h-full flex flex-col min-w-0 max-w-full overflow-hidden">
          <CardHeader className="flex flex-row items-center justify-between pb-2 p-4 sm:p-6 gap-2">
            <div className="flex items-center gap-3 sm:gap-4 mb-4 min-w-0 flex-1">
              <div className="w-8 h-8 rounded-full bg-primary border-primary text-primary-foreground flex items-center justify-center font-bold text-sm shadow-lg shadow-primary/20 scale-110 border-2 shrink-0">
                3
              </div>
              <div className="flex-1 min-w-0">
                <CardTitle className="text-base sm:text-lg">Receba as Provas</CardTitle>
                <CardDescription className="text-xs">Acompanhe em tempo real os arquivos.</CardDescription>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={fetchSessions}
                className="h-10 w-10 hover:bg-primary/5 text-primary shrink-0"
              >
                <RefreshCcw className={cn("w-5 h-5", loadingSessions && "animate-spin")} />
              </Button>
            </div>
          </CardHeader>
          <CardContent className="flex-1 p-3 sm:p-6 pt-0 sm:pt-0">
            <ScrollArea className="h-[800px] pr-2 sm:pr-4">
              <div className="space-y-3">
                {sessions.length === 0 && !loadingSessions && (
                  <div className="py-20 text-center space-y-3 opacity-40">
                    <Clock className="w-10 h-10 mx-auto" />
                    <p className="text-sm">Nenhuma sessão gerada ainda.</p>
                  </div>
                )}

                {sessions.map((s) => (
                  <div
                    key={s.id}
                    className={cn(
                      "group relative p-3 sm:p-4 rounded-xl border transition-all hover:shadow-md min-w-0 max-w-full overflow-hidden",
                      s.status === "active"
                        ? "border-emerald-500/30 bg-emerald-500/5 shadow-inner"
                        : "bg-card hover:bg-muted/30",
                    )}
                  >
                    <div className="flex justify-between items-start mb-2 gap-2">
                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="font-mono text-xs font-bold tracking-tighter text-primary break-all">/{s.token}</p>
                          {getStatusBadge(s.status)}
                        </div>
                        <p className="text-[10px] text-muted-foreground flex items-center gap-1 break-words">
                          <Clock className="w-3 h-3 shrink-0" />
                          <span className="break-words">Criada em: {new Date(s.created_at).toLocaleString()}</span>
                        </p>
                        {aiAlerts[s.id] && (
                          <div className="flex items-center gap-1 mt-1 text-[9px] font-black text-red-500 bg-red-500/10 px-2 py-0.5 rounded-full border border-red-500/20 animate-pulse w-fit">
                            <ShieldAlert className="w-3 h-3" />
                            IA DETECTADA
                          </div>
                        )}
                      </div>
                      <div className="flex gap-1 shrink-0">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => copyLink(s.token)}
                          className="h-7 w-7 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity"
                        >
                          <Copy className="w-3 h-3" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity text-destructive"
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>

                    <div className="flex flex-col gap-3 mt-4">
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="flex items-center gap-2">
                                <div
                                  className={cn(
                                    "w-6 h-6 rounded-full border-2 border-card flex items-center justify-center text-[10px] font-black transition-colors",
                                    (sessionEvidence[s.id]?.length || 0) > 0
                                      ? "bg-emerald-500 text-white"
                                      : "bg-muted text-muted-foreground",
                                  )}
                                >
                                  {sessionEvidence[s.id]?.length || 0}
                                </div>
                                <span className="text-[10px] font-bold text-muted-foreground uppercase">Arquivos</span>
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p className="text-[10px]">{sessionEvidence[s.id]?.length || 0} arquivo(s) recebido(s)</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>

                        <div className="grid grid-cols-1 sm:flex sm:flex-wrap gap-2 w-full sm:w-auto">
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-8 text-[10px] font-black gap-2 border-primary/20 hover:bg-primary/5 w-full sm:w-auto justify-center whitespace-normal"
                            onClick={() => upgradeTimestamps(s.id)}
                            disabled={upgradingId === s.id}
                          >
                            {upgradingId === s.id ? (
                              <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                            ) : (
                              <RefreshCcw className="w-3 h-3 text-orange-500 shrink-0" />
                            )}
                            ATUALIZAR SELO BITCOIN
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-8 text-[10px] font-black gap-2 border-primary/20 hover:bg-primary/5 w-full sm:w-auto justify-center whitespace-normal"
                            onClick={() => exportPDF(s)}
                            disabled={exportingId === s.id}
                          >
                            {exportingId === s.id ? (
                              <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                            ) : (
                              <FileText className="w-3 h-3 shrink-0" />
                            )}
                            GERAR RELATÓRIO
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-8 text-[10px] font-black gap-2 border-primary/20 hover:bg-primary/5 w-full sm:w-auto justify-center whitespace-normal"
                            onClick={() => exportEvidenceZip(s)}
                          >
                            <Archive className="w-3 h-3 shrink-0" />
                            BAIXAR EVIDÊNCIA LACRADA (.ZIP)
                          </Button>
                        </div>
                      </div>

                      {sessionEvidence[s.id] && sessionEvidence[s.id].length > 0 && (
                        <div className="bg-muted/30 rounded-xl p-3 border border-dashed border-border/60">
                          <div className="flex items-center gap-2 mb-2">
                            <Download className="w-3 h-3 text-primary" />
                            <span className="text-[9px] font-black uppercase tracking-widest opacity-60">
                              Arquivos para Download
                            </span>
                          </div>
                          <div className="space-y-1.5 max-h-40 overflow-y-auto pr-2">
                            {sessionEvidence[s.id].map((ev) => (
                              <div
                                key={ev.id}
                                className="flex items-center justify-between p-2 bg-background rounded-lg border border-primary/5 hover:border-primary/20 transition-colors group/item"
                              >
                                <div className="flex items-center gap-2 min-w-0 flex-1">
                                  {getFileIcon(ev.mime_type)}
                                  <span className="text-[10px] font-medium truncate opacity-80">{ev.file_name}</span>
                                </div>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-6 w-6 hover:bg-primary/10 text-primary shrink-0"
                                  onClick={() => downloadFile(ev.file_path, ev.file_name)}
                                >
                                  <Download className="w-3 h-3" />
                                </Button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="bg-amber-500/10 border-2 border-amber-500/40 rounded-xl p-3 flex gap-2 items-start">
                        <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                        <p className="text-[11px] text-amber-700 dark:text-amber-400 leading-snug font-medium">
                          <strong className="block text-[12px] mb-0.5">⏱ Exclusão automática em 72h</strong>
                          Os arquivos e metadados são <strong>apagados em até 72 horas</strong> após o envio pela
                          vítima. Para preservar a prova, <strong>baixe o arquivo localmente agora</strong> e gere o
                          laudo PDF antes do prazo expirar.
                        </p>
                      </div>

                      <div className="bg-primary/5 border-2 border-primary/30 rounded-xl p-3 space-y-2">
                        <div className="flex items-center gap-2">
                          <FileText className="w-4 h-4 text-primary shrink-0" />
                          <strong className="text-[12px] text-foreground">
                            Próximo passo obrigatório — Termo de Arrecadação
                          </strong>
                        </div>
                        <p className="text-[11px] leading-snug text-muted-foreground">
                          Para que esta evidência ingresse formalmente nos autos, a autoridade deve{" "}
                          <strong className="text-foreground">lavrar Termo de Arrecadação</strong> juntando o{" "}
                          <strong className="text-foreground">PDF (Laudo de Cadeia de Custódia)</strong> e o{" "}
                          <strong className="text-foreground">ZIP (Evidência Lacrada)</strong> ao inquérito,
                          referenciando expressamente o{" "}
                          <strong className="text-foreground">
                            ID da Sessão{" "}
                            <code className="px-1 py-0.5 rounded bg-muted text-[10px] font-mono">
                              {s.id.slice(0, 8)}…
                            </code>
                          </strong>{" "}
                          em ambos os documentos.
                        </p>
                        <ol className="text-[10px] leading-snug text-muted-foreground list-decimal pl-4 space-y-0.5">
                          <li>
                            <strong className="text-foreground">Termo de Arrecadação</strong> — formaliza o recebimento
                            e inicia a cadeia de custódia oficial dentro do processo (arts. 158-A a 158-F do CPP).
                          </li>
                          <li>
                            <strong className="text-foreground">Encaminhar ZIP ao IGP/IML ou perito oficial</strong> —
                            bastará rodar <code className="px-1 py-0.5 rounded bg-muted font-mono">sha256sum</code> e
                            conferir com os hashes do PDF.
                          </li>
                          <li>
                            <strong className="text-foreground">TX ID da âncora blockchain</strong> — se disponível no
                            rodapé, anexe ao termo: prova pública e imutável de que os hashes existiam antes de qualquer
                            adulteração.
                          </li>
                        </ol>
                      </div>
                    </div>

                    {aiAlerts[s.id] && (
                      <div className="mt-3 p-3 bg-red-500/5 border border-red-500/20 rounded-lg space-y-2">
                        <div className="flex items-center gap-2 text-[10px] font-black text-red-600">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          ALERTA DE INTEGRIDADE (IA)
                        </div>
                        <p className="text-[10px] text-red-700/80 leading-tight">
                          Foram detectados vestígios de geração sintética (IA) em um ou mais arquivos desta sessão.
                        </p>
                        <Button
                          variant="destructive"
                          size="sm"
                          className="w-full h-7 text-[9px] font-black uppercase tracking-wider"
                          onClick={() => toast.info("Encaminhando para análise pericial detalhada...")}
                        >
                          ENCAMINHAR PARA PERÍCIA OFICIAL
                        </Button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
    </div>
  );
}

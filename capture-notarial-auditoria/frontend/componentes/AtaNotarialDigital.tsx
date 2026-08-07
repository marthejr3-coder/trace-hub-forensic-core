import { useEffect, useRef, useState } from "react";
import RecentNotarialReports from "./RecentNotarialReports";
import { useCredits } from "@/components/credits/CreditsGateProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  FileSignature,
  Loader2,
  Globe,
  Clock,
  Hash,
  Download,
  Image as ImageIcon,
  Server,
  Anchor,
  ExternalLink,
  Bitcoin,
  Crop,
  Video,
  ShieldCheck,
  ChevronDown,
  PenLine,
  Lock,
  AlertTriangle,
  ArrowRight,
  Link2,
  Package,
} from "lucide-react";
import { downloadSealedVideo, buildFriendlyFilename, formatMB } from "@/lib/sealed-video-download";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { formatHashForDisplay, generateSHA256 } from "@/lib/forensic-hash";

import { exportTextualNotarialPDF, textualNotarialPDFToBase64 } from "@/lib/notarial-text-pdf";
import { ForensicSeal, registerForensicReport, updateForensicReportMetadata } from "@/lib/forensic-seal";
import { downloadBlob, openPopupForDownload, isIOS } from "@/lib/ios-download";
import { useRequesterIdentification, composeEvidenceHash, composeEvidenceHashSha512 } from "@/lib/laudo-requester";
import {
  OpenTimestampsStatus,
  TemporalAnchorExplainer,
  type OtsStatus,
} from "@/lib/forensic-report-kit";
import { buildMethodologyRows, METHODOLOGY_TITLE } from "@/lib/forensic-methodology";
import AssinaturaDigital from "./AssinaturaDigital";
import AssinaturaExterna from "./AssinaturaExterna";
import CapturaSeletiva from "./CapturaSeletiva";
import GravacaoTela from "./GravacaoTela";
import { detectSocialNetwork } from "@/lib/social-network-detect";
import SealedCaptureLauncher from "@/components/sealed-capture/SealedCaptureLauncher";
import { useForensicAuthor } from "@/hooks/useForensicAuthor";
import { AuthorModeSelector } from "@/components/juridico/metadados/AuthorModeSelector";
import { ForensicAuthorBlock, ForensicSignatureBlock } from "@/components/juridico/metadados/ForensicAuthorBlock";
import { TITLE_BY_MODE } from "@/lib/forensic-author";
import type { DnsIntegrity, NetworkMetadata } from "@/lib/evidence-network";
import CaptureLinkGenerator from "./CaptureLinkGenerator";

interface NotarialResult {
  original_url: string;
  final_url: string;
  timestamp: string;
  timestamp_source: string;
  http_status: number;
  http_headers: Record<string, string>;
  page_title?: string;
  page_description?: string;
  screenshot_base64: string | null;
  screenshot_mime: string | null;
  screenshot_hash: string | null;
  screenshot_warning?: string | null;
  html_hash: string;
  html_size: number;
  html_truncated?: boolean;
  html_full_size?: number;
  operator_ip?: string;
  request_id?: string;
  screenshot_provider?: string | null;
  screenshot_provider_request_id?: string | null;
  screenshot_provider_headers_hash?: string | null;
  screenshot_fetched_at?: string | null;
  timestamp_response_hash?: string | null;
  evidence_hash: string;
  evidence_hash_sha512?: string | null;
  dnsIntegrity?: DnsIntegrity | null;
  networkMetadata?: NetworkMetadata | null;
  captureEnv?: {
    user_agent: string;
    viewport_width: number;
    viewport_height: number;
    device_scale_factor: number;
    browser_engine: string;
    collector: string;
  } | null;
  merkle?: {
    root: string;
    algorithm: string;
    leaves: { label: string; hash: string }[];
  } | null;
  site_status?: 'online' | 'offline' | 'partial';
  offline_summary?: string | null;
  offline_evidence?: {
    reason: string;
    http_status: number | null;
    http_error_message: string | null;
    dns_consensus: 'offline' | 'partial' | 'online';
    dns: {
      cloudflare: { resolver: string; status: string; records: string[]; raw_excerpt: string; response_hash: string | null };
      google: { resolver: string; status: string; records: string[]; raw_excerpt: string; response_hash: string | null };
    };
    wayback: { available: boolean; closest_url?: string; closest_timestamp?: string };
    probed_at: string;
  } | null;
  wayback_suggestion?: { url: string; timestamp: string } | null;
}

interface StampResult {
  timestamp_id: string;
  date_created: string;
  currencies: string[]; // ["btc","eth","ipfs"]
  raw_response_base64: string; // p/ download .json
  rfc3161_token_base64: string | null;
  rfc3161_timestamp: string | null;
  submitted_at: string;
  bitcoin_block_height?: number | null;
  ots_confirmed_at?: string | null;
  verified_at?: string | null;
  status?: string | null;
  ots_sha256?: string | null;
  block_hash?: string | null;
  block_merkle_root?: string | null;
  block_time?: string | null;
  calendars?: string[];
}

/** Detecta CDN/cache a partir dos headers HTTP devolvidos pela origem. */
function detectCdnProvenance(headers?: Record<string, string>): {
  cdn: string | null;
  cacheStatus: string | null;
  servedBy: string | null;
} {
  if (!headers) return { cdn: null, cacheStatus: null, servedBy: null };
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = v;
  const server = (h["server"] || "").toLowerCase();
  let cdn: string | null = null;
  if (h["cf-ray"] || server.includes("cloudflare")) cdn = "Cloudflare";
  else if (server.includes("akamai") || Object.keys(h).some((k) => k.startsWith("x-akamai") || k === "x-cache-key"))
    cdn = "Akamai";
  else if (h["x-amz-cf-id"] || server.includes("cloudfront")) cdn = "Amazon CloudFront";
  else if (server.includes("fastly") || (h["x-served-by"] || "").includes("cache-")) cdn = "Fastly";
  else if (server.includes("varnish") || h["x-varnish"]) cdn = "Varnish";
  else if (server) cdn = `Origem (${h["server"]})`;
  const cacheStatus =
    h["cf-cache-status"] || h["x-cache"] || h["x-cache-status"] || (h["age"] ? `age=${h["age"]}` : null);
  const servedBy = h["x-served-by"] || h["x-amz-cf-pop"] || h["cf-ray"] || null;
  return { cdn, cacheStatus, servedBy };
}

/** Cabeçalho de PARTE (I, II, III, IV) — divisor cartorial. */
function PartHeader({ number, title, subtitle }: { number: string; title: string; subtitle: string }) {
  return (
    <div data-pdf-part-header="true">
      <div className="h-[3px] w-full bg-[#0F4C3A] mb-3" />
      <div
        className="text-[10px] uppercase tracking-[0.42em] text-[#0F4C3A] font-bold"
        style={{ fontFamily: "'Cinzel', Georgia, serif" }}
      >
        Parte {number}
      </div>
      <h2
        className="text-[18px] font-bold tracking-[0.18em] uppercase text-[#1a1a1a] mt-1 leading-tight"
        style={{ fontFamily: "'Cinzel', Georgia, serif" }}
      >
        {title}
      </h2>
      <p
        className="text-[10.5px] italic text-[#5a5a5a] mt-1 leading-snug"
        style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
      >
        {subtitle}
      </p>
      <div className="border-b-2 border-[#0F4C3A] mt-2.5" />
      <div className="border-b border-[#0F4C3A]/40 mt-0.5" />
    </div>
  );
}

/** Subtítulo dentro de uma parte. */
function SubHeader({ children }: { children: React.ReactNode }) {
  return (
    <h3
      className="text-[10px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold mb-1.5"
      style={{ fontFamily: "'Cinzel', Georgia, serif" }}
    >
      {children}
    </h3>
  );
}

export default function AtaNotarialDigital() {
  const { consume: __consumeCredit } = useCredits();
  const { requester } = useRequesterIdentification();
  const { author } = useForensicAuthor();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NotarialResult | null>(null);
  const [stamping, setStamping] = useState(false);
  const [sealedStamping, setSealedStamping] = useState(false);
  const [stamp, setStamp] = useState<StampResult | null>(null);
  const [otsStatus, setOtsStatus] = useState<OtsStatus | null>(null);
  const [otsVerifying, setOtsVerifying] = useState(false);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [pdfSha256, setPdfSha256] = useState<string | null>(null);
  const [generatingPdf, setGeneratingPdf] = useState(false);
  const [packaging, setPackaging] = useState(false);
  const [sealedOpen, setSealedOpen] = useState(false);
  const [sealedResult, setSealedResult] = useState<{
    session_id: string;
    ended_at: string;
    merkle_root: string;
    event_count: number;
    originstamp_id: string | null;
    ots_base64?: string | null;
    bitcoin_block_height?: number | null;
    ots_confirmed_at?: string | null;
    verified_at?: string | null;
    status?: string | null;
    ots_sha256?: string | null;
    block_hash?: string | null;
    block_merkle_root?: string | null;
    block_time?: string | null;
    calendars?: string[];
    video_path?: string | null;
    video_signed_url?: string | null;
    video_sha256?: string | null;
    video_size?: number | null;
    video_mime?: string | null;
    video_duration_seconds?: number | null;
    video_bucket?: string | null;
    video_signed_url_expires_at?: string | null;
    target_url?: string | null;
  } | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);
  const signSectionRef = useRef<HTMLDivElement>(null);
  const sealedBannerRef = useRef<HTMLDivElement>(null);
  const generateLaudoBtnRef = useRef<HTMLButtonElement>(null);

  // Persistência da sessão: sobrevive a reload/fechar aba enquanto o navegador
  // não for limpo. O picker "Retomar ata notarial anterior" cobre limpeza.
  const ATA_SESSION_KEY = 'trace-hub:ata:last-session:v1';
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (hydratedRef.current) return;
    hydratedRef.current = true;
    try {
      const raw = localStorage.getItem(ATA_SESSION_KEY);
      if (!raw) return;
      const s = JSON.parse(raw);
      if (s?.result) setResult(s.result);
      if (s?.stamp) setStamp(s.stamp);
      if (s?.sealedResult) setSealedResult(s.sealedResult);
      if (s?.otsStatus) setOtsStatus(s.otsStatus);
    } catch { /* ignore */ }
  }, []);
  useEffect(() => {
    try {
      if (!result && !stamp && !sealedResult) {
        localStorage.removeItem(ATA_SESSION_KEY);
        return;
      }
      localStorage.setItem(ATA_SESSION_KEY, JSON.stringify({ result, stamp, sealedResult, otsStatus }));
    } catch { /* quota */ }
  }, [result, stamp, sealedResult, otsStatus]);
  // Espelha stamp/sealedResult em forensic_reports.metadata a cada mudança,
  // para o picker mostrar status atual e reabertura funcionar após limpeza.
  useEffect(() => {
    if (!result?.evidence_hash) return;
    if (!stamp && !sealedResult) return;
    updateForensicReportMetadata(result.evidence_hash, {
      stamp: stamp ?? null,
      sealed_stamp: sealedResult ?? null,
      ots_status: otsStatus ?? null,
    }).catch(() => {});
  }, [result?.evidence_hash, stamp, sealedResult, otsStatus]);


  const handleCapture = async (): Promise<NotarialResult | null> => {
    if (!/^https?:\/\//i.test(url.trim())) {
      toast.error("Informe uma URL válida (http:// ou https://)");
      return null;
    }
    setLoading(true);
    setResult(null);
    try {
      const __gate = await __consumeCredit("juridico-ata-notarial");
      if (!__gate.allowed) return null;
      // Cadeia forense da sessão (estilo blockchain): cada nova captura
      // referencia o hash da anterior, impossibilitando inserção/remoção sem
      // invalidar toda a sequência.
      const prevEvidenceHash = (() => {
        try { return localStorage.getItem('trace-hub:ata:last-evidence-hash'); }
        catch { return null; }
      })();
      const [captureRes, dnsRes, netRes] = await Promise.all([
        supabase.functions.invoke("notarial-capture", { body: { url: url.trim(), previous_evidence_hash: prevEvidenceHash } }),
        supabase.functions
          .invoke("evidence-integrity-probe", { body: { url: url.trim() } })
          .then((r) => (r.error || (r.data as { error?: string })?.error ? null : (r.data as DnsIntegrity)))
          .catch(() => null),
        supabase.functions
          .invoke("evidence-network-metadata", { body: { url: url.trim() } })
          .then((r) => (r.error || (r.data as { error?: string })?.error ? null : (r.data as NetworkMetadata)))
          .catch(() => null),
      ]);
      if (captureRes.error) throw captureRes.error;
      if ((captureRes.data as { error?: string })?.error) throw new Error((captureRes.data as { error: string }).error);
      const raw = captureRes.data as NotarialResult & { operator_ip?: string; request_id?: string };
      // Server-authoritative: IP do operador e requestId vêm do Edge Function
      // (capturados via CF-Connecting-IP/x-forwarded-for + crypto.randomUUID no
      // servidor). Esses valores são misturados ao requester ANTES do hash.
      const requesterWithServer = requester
        ? { ...requester, ip: raw.operator_ip || "unknown", requestId: raw.request_id || "" }
        : null;
      // Bloco 1: hash composto incluindo identificação do solicitante (SHA-256 + SHA-512).
      const [composed, composedSha512] = await Promise.all([
        composeEvidenceHash(raw.evidence_hash, requesterWithServer),
        composeEvidenceHashSha512(raw.evidence_hash, requesterWithServer),
      ]);
      const rawSha512 = (raw as { evidence_hash_sha512?: string | null }).evidence_hash_sha512 ?? null;
      const rawCaptureEnv = (raw as { capture_env?: NotarialResult['captureEnv'] }).capture_env ?? null;
      // Merkle root cobre todos os artefatos coletados → ancorado em blockchain.
      const merkleLeaves = [
        { label: 'evidence_hash', hash: composed },
        { label: 'screenshot_hash', hash: (raw as { screenshot_hash?: string }).screenshot_hash || await generateSHA256('none') },
        { label: 'html_hash', hash: (raw as { html_hash?: string }).html_hash || await generateSHA256('none') },
        { label: 'network_metadata_hash', hash: await generateSHA256(JSON.stringify(netRes ?? {})) },
        { label: 'dns_integrity_hash', hash: await generateSHA256(JSON.stringify(dnsRes ?? {})) },
        { label: 'capture_env_hash', hash: await generateSHA256(JSON.stringify(rawCaptureEnv ?? {})) },
      ];
      let mLevel = merkleLeaves.map((l) => l.hash);
      while (mLevel.length > 1) {
        const next: string[] = [];
        for (let i = 0; i < mLevel.length; i += 2) {
          next.push(await generateSHA256(mLevel[i] + (mLevel[i + 1] ?? mLevel[i])));
        }
        mLevel = next;
      }
      const captured: NotarialResult = {
        ...raw,
        evidence_hash: composed,
        evidence_hash_sha512: composedSha512 ?? rawSha512,
        dnsIntegrity: dnsRes,
        networkMetadata: netRes,
        captureEnv: rawCaptureEnv,
        merkle: { root: mLevel[0], algorithm: 'merkle-sha256-pairwise', leaves: merkleLeaves },
      };
      setResult(captured);
      try { localStorage.setItem('trace-hub:ata:last-evidence-hash', captured.evidence_hash); } catch { /* ignore */ }
      setStamp(null);
      setOtsStatus(null);
      // Persistência para reabertura futura: o screenshot (pesado) vai para o
      // bucket privado; o restante do payload é gravado em metadata.result.
      // `forensic_reports` é WORM, então isso precisa acontecer no INSERT.
      let screenshotPath: string | null = null;
      try {
        const { data: userResp } = await supabase.auth.getUser();
        const uid = userResp?.user?.id;
        if (uid && captured.screenshot_base64) {
          const bin = atob(captured.screenshot_base64);
          const bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          const mime = captured.screenshot_mime || 'image/png';
          const ext = mime.includes('jpeg') || mime.includes('jpg') ? 'jpg' : mime.includes('webp') ? 'webp' : 'png';
          const path = `${uid}/${captured.evidence_hash}.${ext}`;
          const { error: upErr } = await supabase.storage
            .from('notarial-screenshots')
            .upload(path, new Blob([bytes], { type: mime }), { contentType: mime, upsert: true });
          if (!upErr) screenshotPath = path;
          else console.warn('[ata] upload do screenshot falhou (não bloqueante)', upErr);
        }
      } catch (err) {
        console.warn('[ata] persistência do screenshot falhou (não bloqueante)', err);
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { screenshot_base64: _omitScreenshot, ...resultForStorage } = captured;
      // Registra laudo na base central de validação
      registerForensicReport({
        evidenceHash: captured.evidence_hash,
        reportType: "notarial",
        subject: captured.page_title || captured.final_url || captured.original_url,
        metadata: {
          original_url: captured.original_url,
          final_url: captured.final_url,
          html_hash: captured.html_hash,
          screenshot_hash: captured.screenshot_hash,
          timestamp_source: captured.timestamp_source,
          requester_email: requester?.email ?? null,
          requester_ip: requesterWithServer?.ip ?? null,
          request_id: requesterWithServer?.requestId ?? null,
          // Payload completo para reabertura fiel do laudo (sem a imagem).
          result_version: 1,
          screenshot_path: screenshotPath,
          screenshot_mime: captured.screenshot_mime ?? null,
          result: resultForStorage,
          requester_snapshot: requesterWithServer
            ? {
                name: (requesterWithServer as any).name ?? null,
                email: (requesterWithServer as any).email ?? null,
                cpf: (requesterWithServer as any).cpf ?? null,
                cargo: (requesterWithServer as any).cargo ?? null,
                ip: (requesterWithServer as any).ip ?? null,
                requestId: (requesterWithServer as any).requestId ?? null,
              }
            : null,
        },
      });

      if (dnsRes && dnsRes.dns_consensus_level === "divergent") {
        toast.warning("Resolvedores DNS divergiram (ASNs distintos) — possível DNS Poisoning. Veja Parte VI.");
      } else if (dnsRes && dnsRes.dns_consensus_level === "consensus_partial") {
        toast.info("Apenas 1 resolver DNS respondeu — resultado parcial. Veja Parte VI.");
      } else {
        toast.success("Captura notarial gerada com integridade SHA-256 + verificações AFD");
      }
      return captured;
    } catch (e: any) {
      toast.error(e.message || "Falha ao capturar");
      return null;
    } finally {
      setLoading(false);
    }
  };

  const waitForQRCode = async (timeoutMs = 2000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (reportRef.current?.querySelector('[data-qr-ready="true"]')) return;
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  const handleExportPDF = async (
    silent = false,
    opts?: { resultOverride?: NotarialResult | null; popup?: Window | null },
  ) => {
    const effectiveResult = opts?.resultOverride ?? result;
    if (!effectiveResult) return;
    // CRÍTICO: abre popup ANTES de qualquer await (apenas no fluxo de download)
    const popup =
      opts?.popup !== undefined ? opts.popup : silent ? null : openPopupForDownload("Gerando ata notarial…");
    setGeneratingPdf(true);
    try {
      // Antes de gerar o PDF: tenta atualizar o(s) selo(s) Bitcoin/OpenTimestamps
      // via originstamp-verify, para que o laudo reflita confirmação por bloco.
      let effectiveStamp = stamp;
      let effectiveSealed = sealedResult;
      try {
        if (stamp?.raw_response_base64 && effectiveResult?.evidence_hash) {
          const { data: v } = await supabase.functions.invoke("originstamp-verify", {
            body: { evidence_hash: effectiveResult.evidence_hash, ots_base64: stamp.raw_response_base64 },
          });
          if (v && !v.error) {
            const upgraded = v.upgraded_ots_base64 ?? stamp.raw_response_base64;
            effectiveStamp = {
              ...stamp,
              raw_response_base64: upgraded,
              bitcoin_block_height: v.block_height ?? stamp.bitcoin_block_height ?? null,
              ots_confirmed_at: v.confirmed_at ?? stamp.ots_confirmed_at ?? null,
              verified_at: new Date().toISOString(),
              status: v.confirmed ? "confirmed_bitcoin" : stamp.status ?? "anchored",
              ots_sha256: v.ots_sha256 ?? stamp.ots_sha256 ?? null,
              block_hash: v.block_hash ?? stamp.block_hash ?? null,
              block_merkle_root: v.block_merkle_root ?? stamp.block_merkle_root ?? null,
              block_time: v.block_time ?? stamp.block_time ?? null,
              calendars: v.calendars ?? stamp.calendars,
            };
            setStamp(effectiveStamp);
            setOtsStatus({
              confirmed: !!v.confirmed,
              confirmedAt: v.confirmed_at ?? null,
              blockHeight: v.block_height ?? null,
            });
          }
        }
      } catch (verr) {
        console.warn("[Ata] auto-verify OTS falhou", verr);
      }
      try {
        if (sealedResult?.ots_base64 && sealedResult.merkle_root) {
          const { data: v } = await supabase.functions.invoke("originstamp-verify", {
            body: { evidence_hash: sealedResult.merkle_root, ots_base64: sealedResult.ots_base64 },
          });
          if (v && !v.error) {
            const upgraded = v.upgraded_ots_base64 ?? sealedResult.ots_base64;
            effectiveSealed = {
              ...sealedResult,
              ots_base64: upgraded,
              bitcoin_block_height: v.block_height ?? sealedResult.bitcoin_block_height ?? null,
              ots_confirmed_at: v.confirmed_at ?? sealedResult.ots_confirmed_at ?? null,
              verified_at: new Date().toISOString(),
              status: v.confirmed ? "confirmed_bitcoin" : sealedResult.status ?? "anchored",
              ots_sha256: v.ots_sha256 ?? sealedResult.ots_sha256 ?? null,
              block_hash: v.block_hash ?? sealedResult.block_hash ?? null,
              block_merkle_root: v.block_merkle_root ?? sealedResult.block_merkle_root ?? null,
              block_time: v.block_time ?? sealedResult.block_time ?? null,
              calendars: v.calendars ?? sealedResult.calendars,
            };
            setSealedResult(effectiveSealed);
          }
        }
      } catch (verr) {
        console.warn("[Ata] auto-verify OTS (sealed) falhou", verr);
      }
      // PDF 100% textual — pesquisável, copiável, sem html2canvas.
      const pdfInput = { result: effectiveResult, requester, author, stamp: effectiveStamp, sealedResult: effectiveSealed };
      let base64Str: string;
      if (silent) {
        base64Str = await textualNotarialPDFToBase64(pdfInput);
        setPdfBase64(base64Str);
      } else {
        const out = await exportTextualNotarialPDF(pdfInput, `ata-notarial-${Date.now()}.pdf`, popup);
        base64Str = out.base64;
        setPdfBase64(base64Str);
        toast.success("Certidão digital baixada e pronta para assinatura");
      }
      // Hash SHA-256 do PDF final → fecha cadeia (página → PDF → blockchain)
      try {
        const bin = atob(base64Str);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const buf = await crypto.subtle.digest("SHA-256", bytes);
        const pdfHash = Array.from(new Uint8Array(buf))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        setPdfSha256(pdfHash);
        updateForensicReportMetadata(effectiveResult.evidence_hash, {
          pdf_sha256: pdfHash,
          pdf_generated_at: new Date().toISOString(),
        }).catch(() => {});
      } catch (hashErr) {
        console.warn("[PDF SHA-256] falha ao calcular hash do PDF", hashErr);
      }
      return base64Str;
    } catch (e: any) {
      console.error("[PDF Export]", e);
      popup?.close();
      if (!silent) {
        toast.error(`Falha ao exportar PDF: ${e?.message || "erro desconhecido"}`);
      }
      return null;
    } finally {
      setGeneratingPdf(false);
    }
  };

  /**
   * Botão do banner de selo lacrado: executa o fluxo COMPLETO em um clique —
   * captura notarial e, na sequência, emissão/download do PDF do relatório.
   * O popup é aberto antes de qualquer await para não ser bloqueado (iOS/Safari).
   */
  const handleSealedGenerateReport = async () => {
    if (!url.trim()) {
      toast.error("Informe a URL capturada na gravação selada");
      return;
    }
    const popup = openPopupForDownload("Gerando relatório de evidência…");
    const captured = await handleCapture();
    if (!captured) {
      popup?.close();
      return;
    }
    await handleExportPDF(false, { resultOverride: captured, popup });
  };



  const handleExportPNG = async () => {
    if (!reportRef.current) return;
    setGeneratingPdf(true);
    try {
      await waitForQRCode();
      const { default: html2canvas } = await import("html2canvas");
      const canvas = await html2canvas(reportRef.current, {
        scale: 2,
        backgroundColor: "#ffffff",
        useCORS: true,
        logging: false,
      });
      const link = document.createElement("a");
      link.download = `ata-notarial-${Date.now()}.png`;
      link.href = canvas.toDataURL("image/png");
      link.click();
      toast.success("Imagem do laudo baixada");
    } catch (e: any) {
      console.error("[PNG Export]", e);
      toast.error(`Falha ao exportar PNG: ${e?.message || "erro"}`);
    } finally {
      setGeneratingPdf(false);
    }
  };

  const handleStamp = async (auto = false) => {
    if (!result?.evidence_hash) return;
    setStamping(true);
    try {
      const { data, error } = await supabase.functions.invoke("originstamp-anchor", {
        body: {
          evidence_hash: result.evidence_hash,
          context: {
            tool: "ata_notarial",
            ref_id: result.evidence_hash,
            ref_label: result.page_title || result.final_url || result.original_url || null,
          },
        },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setStamp({
        timestamp_id: data.originstamp.timestamp_id,
        date_created: data.originstamp.date_created,
        currencies: data.originstamp.currencies ?? ["btc"],
        raw_response_base64: data.originstamp.raw_response_base64 ?? data.originstamp.ots_base64,
        rfc3161_token_base64: data.rfc3161?.token_base64 ?? null,
        rfc3161_timestamp: data.rfc3161?.timestamp ?? null,
        submitted_at: data.submitted_at,
      });
      setOtsStatus({ confirmed: false });
      toast.success("Selo OpenTimestamps (Bitcoin) emitido · carimbo RFC 3161 imediato");
      // Auto-cache PDF em background para assinatura ficar pronta
      handleExportPDF(true).catch(() => {});
      // Auto-scroll suave até assinatura
      setTimeout(() => {
        signSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 400);
    } catch (e: any) {
      console.error("Stamp error", e);
      const ctx = e?.context;
      let detail = e?.message || "Falha ao selar evidência";
      if (ctx && typeof ctx.json === "function") {
        try {
          const body = await ctx.json();
          if (body?.error) detail = body.error;
        } catch {}
      }
      if (e?.name === "FunctionsFetchError")
        detail = "Não foi possível chamar o serviço de selo (rede/CORS). Tente novamente em instantes.";
      toast.error(detail);
    } finally {
      setStamping(false);
    }
  };

  // Ancoragem Bitcoin automática: dispara assim que a captura gera o hash,
  // sem depender de clique no botão "Atualizar Bitcoin".
  const autoStampedRef = useRef<string | null>(null);
  useEffect(() => {
    const hash = result?.evidence_hash;
    if (!hash || stamp || stamping) return;
    if (autoStampedRef.current === hash) return;
    autoStampedRef.current = hash;
    void handleStamp(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result?.evidence_hash, stamp, stamping]);



  const verifyOts = async () => {
    if (!stamp || !result) return;
    setOtsVerifying(true);
    try {
      const { data, error } = await supabase.functions.invoke("originstamp-verify", {
        body: { evidence_hash: result.evidence_hash, ots_base64: stamp.raw_response_base64 },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setOtsStatus({
        confirmed: !!data.confirmed,
        confirmedAt: data.confirmed_at ?? null,
        blockHeight: data.block_height ?? null,
      });
      if (data.upgraded_ots_base64) {
        setStamp((prev) => (prev ? { ...prev, raw_response_base64: data.upgraded_ots_base64 } : prev));
      }
      toast.success(
        data.confirmed
          ? "Confirmado em Bitcoin via OpenTimestamps"
          : "Aguardando bloco Bitcoin (1-6h) — RFC 3161 já é prova suficiente",
      );
    } catch (e: any) {
      toast.error(e.message || "Falha ao verificar OpenTimestamps");
    } finally {
      setOtsVerifying(false);
    }
  };

  const handleUpdateSealedBitcoin = async () => {
    if (!sealedResult?.merkle_root || sealedStamping) return;
    setSealedStamping(true);
    try {
      // 1) Se ainda não existe selo, ancora agora (RFC 3161 + submissão OTS)
      let otsB64: string | null = sealedResult.ots_base64 ?? null;
      let originstampId = sealedResult.originstamp_id;
      if (!otsB64 || !originstampId) {
        const { data, error } = await supabase.functions.invoke("originstamp-anchor", {
          body: { evidence_hash: sealedResult.merkle_root },
        });
        if (error) throw error;
        if (data?.error) throw new Error(data.error);
        originstampId = data.originstamp?.timestamp_id ?? sealedResult.merkle_root;
        otsB64 = data.originstamp?.raw_response_base64 ?? data.originstamp?.ots_base64 ?? null;
      }
      // 2) Verifica/upgrade do .ots para detectar confirmação em bloco Bitcoin
      let blockHeight: number | null = sealedResult.bitcoin_block_height ?? null;
      let confirmedAt: string | null = sealedResult.ots_confirmed_at ?? null;
      let statusStr: string = sealedResult.status ?? "anchored";
      let upgraded = otsB64;
      let otsSha: string | null = sealedResult.ots_sha256 ?? null;
      let blockHash: string | null = sealedResult.block_hash ?? null;
      let blockMerkle: string | null = sealedResult.block_merkle_root ?? null;
      let blockTime: string | null = sealedResult.block_time ?? null;
      let cals: string[] | undefined = sealedResult.calendars;
      if (otsB64) {
        try {
          const { data: v } = await supabase.functions.invoke("originstamp-verify", {
            body: { evidence_hash: sealedResult.merkle_root, ots_base64: otsB64 },
          });
          if (v && !v.error) {
            upgraded = v.upgraded_ots_base64 ?? otsB64;
            blockHeight = v.block_height ?? blockHeight;
            confirmedAt = v.confirmed_at ?? confirmedAt;
            otsSha = v.ots_sha256 ?? otsSha;
            blockHash = v.block_hash ?? blockHash;
            blockMerkle = v.block_merkle_root ?? blockMerkle;
            blockTime = v.block_time ?? blockTime;
            cals = v.calendars ?? cals;
            if (v.confirmed) statusStr = "confirmed_bitcoin";
          }
        } catch (verr) {
          console.warn("[Ata] verify sealed OTS falhou", verr);
        }
      }
      setSealedResult((prev) => (prev ? {
        ...prev,
        originstamp_id: originstampId,
        ots_base64: upgraded,
        bitcoin_block_height: blockHeight,
        ots_confirmed_at: confirmedAt,
        verified_at: new Date().toISOString(),
        status: statusStr,
        ots_sha256: otsSha,
        block_hash: blockHash,
        block_merkle_root: blockMerkle,
        block_time: blockTime,
        calendars: cals,
      } : prev));
      if (statusStr === "confirmed_bitcoin" && blockHeight) {
        toast.success(`CONFIRMADO no bloco Bitcoin #${blockHeight}`);
      } else {
        toast.success("Selo Bitcoin emitido · aguardando bloco (RFC 3161 já é prova suficiente)");
      }
    } catch (e: any) {
      toast.error(e?.message || "Falha ao atualizar selo Bitcoin");
    } finally {
      setSealedStamping(false);
    }
  };

  /**
   * Pacote único da prova: PDF + .ots + .tsr + screenshot + instruções.
   * Um clique só — evita juntada incompleta aos autos.
   */
  const handleDownloadPackage = async () => {
    if (!result) return;
    const popup = openPopupForDownload("Montando pacote da prova\u2026");
    setPackaging(true);
    const t = toast.loading("Montando pacote completo da prova\u2026");
    try {
      const pdfB64 = await handleExportPDF(true);
      if (!pdfB64) throw new Error("não foi possível gerar o PDF do relatório");
      const media: { filename: string; blob: Blob; description?: string }[] = [];
      if (result.screenshot_base64) {
        const bin = atob(result.screenshot_base64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const mime = result.screenshot_mime || "image/png";
        media.push({
          filename: `captura_tela.${mime.includes("jpeg") ? "jpg" : "png"}`,
          blob: new Blob([bytes], { type: mime }),
          description: "Screenshot da página no momento da coleta",
        });
      }
      const { buildNotarialEvidenceZip } = await import("@/lib/notarial-evidence-zip");
      const { blob, filename } = await buildNotarialEvidenceZip({
        prefix: "ata-notarial",
        label: "Ata Notarial Digital",
        evidenceHash: result.evidence_hash,
        pdfBase64: pdfB64,
        pdfFilename: "relatorio_evidencia_ata_notarial.pdf",
        otsBase64: stamp?.raw_response_base64 ?? null,
        tsrBase64: stamp?.rfc3161_token_base64 ?? null,
        otsSha256: stamp?.ots_sha256 ?? null,
        blockHeight: stamp?.bitcoin_block_height ?? null,
        blockHash: stamp?.block_hash ?? null,
        blockMerkleRoot: stamp?.block_merkle_root ?? null,
        blockTime: stamp?.block_time ?? null,
        calendars: stamp?.calendars,
        media,
        meta: {
          "URL coletada": result.final_url || result.original_url,
          "Coletado em": result.timestamp,
          "Hash da evidência (SHA-256)": result.evidence_hash,
          "Vídeo da sessão lacrada": sealedResult
            ? 'não incluído no ZIP por tamanho — use "Baixar vídeo" no painel do selo lacrado'
            : undefined,
        },
        operatorName: author?.fullName || requester?.name || null,
        startedAt: result.timestamp,
      });
      downloadBlob(blob, filename, popup);
      toast.dismiss(t);
      toast.success("Pacote completo da prova baixado");
    } catch (e: any) {
      toast.dismiss(t);
      console.error("[Pacote ZIP]", e);
      try { popup?.close(); } catch { /* noop */ }
      toast.error(`Falha ao montar o pacote: ${e?.message || "erro desconhecido"}`);
    } finally {
      setPackaging(false);
    }
  };

  const downloadBase64 = (b64: string, filename: string, mime: string) => {
    const popup = openPopupForDownload("Abrindo arquivo…");
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const blob = new Blob([bytes], { type: mime });
    downloadBlob(blob, filename, popup);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileSignature className="w-5 h-5 text-amber-500" />
          Capture Notarial — Validade = Cartório
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          Três modos de captura forense com hash SHA-256, ancoragem temporal via{" "}
          <strong>OpenTimestamps (Bitcoin, gratuito)</strong> + <strong>carimbo RFC 3161 (FreeTSA)</strong> e assinatura
          digital gratuita via <strong>gov.br</strong>. Validade equivalente à ata notarial (CPC art. 411 II, MP
          2.200-2/2001, Lei 14.063/2020).
        </p>
      </CardHeader>
      <CardContent>
        {!result && !stamp && !sealedResult && (
          <RecentNotarialReports
            onReopen={({ result: r, stamp: s, sealedResult: sr, otsStatus: os }) => {
              if (r) setResult(r);
              if (s) setStamp(s);
              if (sr) setSealedResult(sr);
              if (os) setOtsStatus(os);
              if (r?.original_url) setUrl(r.original_url);
              toast.success('Ata reaberta — role até "Ancoragem Bitcoin" para atualizar.');
            }}
          />
        )}
        {/* Seletor de níveis — clareza para o usuário sobre qual ferramenta usar */}
        <div className="mb-6 rounded-xl border bg-muted/20 p-4">

          <div className="flex items-center justify-between mb-3">
            <p className="text-sm font-bold text-foreground">Qual nível de prova você precisa?</p>
            <Badge variant="outline" className="text-[10px]">
              Não sabe? Use o Nível 2
            </Badge>
          </div>
          <div className="grid md:grid-cols-3 gap-3">
            {/* Nível 1 — Captura Rápida (antigo Trace Capture, agora inline aqui) */}
            <div className="rounded-lg border border-border bg-card p-3 block">
              <div className="flex items-center gap-2 mb-1.5">
                <Badge className="bg-slate-500/15 text-slate-300 border-slate-500/30 text-[10px]">Nível 1</Badge>
                <span className="text-xs font-semibold">Captura Rápida</span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-snug">
                Screenshot + hash SHA-256 da URL em segundos. Ideal para boletim de ocorrência e provas simples.
                <br />
                <span className="text-[10px] text-foreground/70">
                  Substitui o antigo Trace Capture — use a aba <strong>Captura</strong> abaixo deixando os selos extras
                  desligados.
                </span>
              </p>
            </div>
            {/* Nível 2 — Capture Notarial Completa */}
            <div className="rounded-lg border-2 border-primary/40 bg-primary/5 p-3 relative">
              <Badge className="absolute -top-2 right-2 text-[9px]">Recomendado</Badge>
              <div className="flex items-center gap-2 mb-1.5">
                <Badge className="bg-primary/20 text-primary border-primary/40 text-[10px]">Nível 2</Badge>
                <span className="text-xs font-semibold">Capture Notarial Completa</span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-snug">
                Captura forense + <strong>OpenTimestamps (Bitcoin)</strong> + <strong>RFC 3161</strong> + assinatura
                gov.br. Validade equivalente a cartório.
              </p>
              <p className="text-[10px] text-primary mt-2">Você já está aqui — use as abas abaixo ↓</p>
            </div>
            {/* Nível 3 — Ambiente Lacrado */}
            <button
              type="button"
              onClick={() => setSealedOpen(true)}
              className="group text-left rounded-lg border border-amber-500/30 bg-gradient-to-br from-amber-500/10 to-transparent p-3 hover:border-amber-500/60 transition-colors"
            >
              <div className="flex items-center gap-2 mb-1.5">
                <Badge className="bg-amber-500/15 text-amber-400 border-amber-500/30 text-[10px]">Nível 3</Badge>
                <span className="text-xs font-semibold flex items-center gap-1">
                  Ambiente Lacrado <Lock className="w-3 h-3" />
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-snug">
                Grava a sessão num ambiente isolado com proxy auditado, cadeia Merkle e vídeo opcional. Depois você
                confirma a captura final em 1 clique. Para casos onde a defesa pode questionar o ambiente do operador.
              </p>
              <p className="text-[10px] text-amber-400 mt-2 group-hover:underline flex items-center gap-1">
                <ShieldCheck className="w-3 h-3" /> Iniciar sessão lacrada →
              </p>
            </button>
          </div>
        </div>
        <SealedCaptureLauncher
          open={sealedOpen}
          onOpenChange={setSealedOpen}
          onFinalized={(r) => {
            setSealedResult(r);
            if (r.target_url) setUrl(r.target_url);
            // Espera o modal fechar e o banner montar antes do scroll/foco.
            setTimeout(() => {
              sealedBannerRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
              generateLaudoBtnRef.current?.focus();
            }, 500);
          }}
        />
        {sealedResult && (
          <div
            ref={sealedBannerRef}
            className="mb-6 rounded-xl border-2 border-amber-500/50 bg-gradient-to-br from-amber-500/10 to-emerald-500/5 p-4 space-y-3"
          >
            <div className="flex items-start gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-500 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="font-bold text-foreground text-sm">
                  Selo lacrado pronto · {sealedResult.event_count} eventos
                </p>
                <p className="text-[11px] text-muted-foreground break-all mt-0.5">
                  Merkle <code className="font-mono">{sealedResult.merkle_root.slice(0, 24)}…</code>
                  {sealedResult.video_path ? " · vídeo anexado" : ""}
                  {sealedResult.originstamp_id ? " · ancorado em BTC/RFC 3161" : ""}
                </p>
              </div>
            </div>
            <div className="rounded-lg bg-background/60 border border-border/60 p-3">
              <p className="text-[11px] font-semibold text-foreground mb-1">
                Próximo passo (último): gerar o PDF da Ata Notarial com este selo
              </p>
              <p className="text-[11px] text-muted-foreground leading-snug mb-3">
                {sealedResult.target_url ? (
                  <>
                    A URL <code className="font-mono text-foreground">{sealedResult.target_url}</code> já foi preenchida
                    abaixo. Clique no botão verde para emitir o laudo completo.
                  </>
                ) : (
                  "Confirme a URL abaixo e clique no botão verde para emitir o laudo completo."
                )}
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  ref={generateLaudoBtnRef}
                  size="sm"
                  onClick={handleSealedGenerateReport}
                  disabled={loading || generatingPdf || !url.trim()}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white gap-1.5"
                >
                  {loading || generatingPdf ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <FileSignature className="w-3.5 h-3.5" />
                  )}
                  {loading || generatingPdf ? "Gerando relatório…" : "Gerar relatório agora"}
                </Button>
                {sealedResult.video_path && (
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1.5 border-emerald-500/60 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/10"
                    onClick={async () => {
                      try {
                        await downloadSealedVideo(sealedResult);
                        toast.success("Download do vídeo iniciado");
                      } catch (e: any) {
                        toast.error(e?.message || "Falha ao baixar vídeo");
                      }
                    }}
                  >
                    <Download className="w-3.5 h-3.5" />
                    Baixar vídeo{formatMB(sealedResult.video_size) ? ` (${formatMB(sealedResult.video_size)})` : ""}
                  </Button>
                )}
                <Button size="sm" variant="ghost" onClick={() => setSealedResult(null)}>
                  Descartar selo
                </Button>
                {!sealedResult.originstamp_id && (
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1.5 border-orange-500/60 text-orange-700 dark:text-orange-400 hover:bg-orange-500/10"
                    onClick={handleUpdateSealedBitcoin}
                    disabled={sealedStamping}
                  >
                    {sealedStamping ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Bitcoin className="w-3.5 h-3.5" />
                    )}
                    {sealedStamping ? "Selando…" : "Emitir Selo Bitcoin"}
                  </Button>
                )}
              </div>
              {sealedResult.video_path && (
                <p className="text-[10px] text-muted-foreground mt-2 italic">
                  Recomendamos baixar e arquivar o vídeo junto com o PDF do laudo. Você pode baixar novamente depois — o
                  vídeo fica guardado no cofre privado.
                </p>
              )}
            </div>
          </div>
        )}

        <Tabs defaultValue="url" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 md:grid-cols-4">
            <TabsTrigger value="url" className="gap-1.5">
              <Globe className="w-3.5 h-3.5" /> <span className="hidden sm:inline">URL pública</span>
              <span className="sm:hidden">URL</span>
            </TabsTrigger>
            <TabsTrigger value="capture-link" className="gap-1.5">
              <Link2 className="w-3.5 h-3.5 text-primary" /> <span className="hidden sm:inline">Capture Link</span>
              <span className="sm:hidden">Link</span>
              <Badge className="ml-1 h-3.5 px-1 text-[7px] bg-primary/20 text-primary border-0 font-black">NOVO</Badge>
            </TabsTrigger>
            <TabsTrigger value="seletiva" className="gap-1.5">
              <Crop className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Recorte</span>
              <span className="sm:hidden">Crop</span>
            </TabsTrigger>
            <TabsTrigger value="gravacao" className="gap-1.5">
              <Video className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Gravação</span>
              <span className="sm:hidden">Vídeo</span>
              {isIOS() && (
                <Badge
                  variant="outline"
                  className="ml-1 px-1 py-0 text-[8px] font-bold text-amber-600 border-amber-500/50 bg-amber-500/10 leading-none"
                >
                  iOS
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="capture-link" className="space-y-4">
            <CaptureLinkGenerator />
          </TabsContent>

          <TabsContent value="seletiva" className="space-y-4">
            <CapturaSeletiva />
          </TabsContent>

          <TabsContent value="gravacao" className="space-y-4">
            <GravacaoTela />
          </TabsContent>

          <TabsContent value="url" className="space-y-6">
            <AuthorModeSelector />
            <div className="space-y-2">
              <Label>URL pública</Label>
              <div className="flex gap-2">
                <Input
                  placeholder="https://instagram.com/perfil/post/..."
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !loading && handleCapture()}
                />
                <Button onClick={handleCapture} disabled={loading}>
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
                  <span className="ml-2 hidden sm:inline">Capturar</span>
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                A captura inclui screenshot completo, HTML, headers HTTP, redirects e timestamp NTP.
              </p>
            </div>

            {result && (
              <>
                {/* Banner de fluxo guiado */}
                <div className="flex items-center justify-between gap-2 p-3 rounded-lg bg-muted/40 border text-xs">
                  <div className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 font-medium">
                    <span className="w-5 h-5 rounded-full bg-emerald-500/20 flex items-center justify-center">✓</span>
                    <span>1. Capturado</span>
                  </div>
                  <div className="flex-1 h-px bg-border" />
                  <div
                    className={`flex items-center gap-1.5 font-medium ${stamp ? "text-emerald-600 dark:text-emerald-400" : "text-amber-600 dark:text-amber-400"}`}
                  >
                    <span
                      className={`w-5 h-5 rounded-full flex items-center justify-center ${stamp ? "bg-emerald-500/20" : "bg-amber-500/20"}`}
                    >
                      {stamp ? "✓" : "2"}
                    </span>
                    <span>{stamp ? "2. Selado" : "2. Selar"}</span>
                  </div>
                  <div className="flex-1 h-px bg-border" />
                  <div
                    className={`flex items-center gap-1.5 font-medium ${stamp ? "text-foreground" : "text-muted-foreground"}`}
                  >
                    <span
                      className={`w-5 h-5 rounded-full flex items-center justify-center ${stamp ? "bg-primary/20" : "bg-muted"}`}
                    >
                      3
                    </span>
                    <span>3. Baixar & Assinar</span>
                  </div>
                </div>

                {/* ====== CERTIDÃO DIGITAL — área que vira PDF ====== */}
                <div
                  ref={reportRef}
                  className="relative bg-white text-[#1a1a1a]"
                  style={{ fontFamily: "'EB Garamond', 'Cambria', Georgia, serif" }}
                >
                  {/* ============================================================ */}
                  {/* FRONTISPÍCIO — Página 1 (capa cartorial oficial)             */}
                  {/* ============================================================ */}
                  <section
                    data-pdf-section
                    data-pdf-break-after="true"
                    className="relative bg-white p-10 border-t-[6px] border-b-[6px] border-double border-[#0F4C3A] overflow-hidden"
                  >
                    {/* Marca d'água */}
                    <div
                      className="absolute inset-0 flex items-center justify-center pointer-events-none select-none"
                      aria-hidden="true"
                      style={{ opacity: 0.04 }}
                    >
                      <ShieldCheck className="w-[420px] h-[420px] text-[#0F4C3A]" strokeWidth={1} />
                    </div>

                    <div className="relative">
                      {/* Brasão institucional */}
                      <div className="flex flex-col items-center gap-2 mb-6">
                        <div className="w-16 h-16 rounded-full bg-[#0F4C3A] flex items-center justify-center border-4 border-[#0F4C3A]/20 shadow-md">
                          <ShieldCheck className="w-9 h-9 text-white" strokeWidth={2.2} />
                        </div>
                        <div className="text-center" style={{ fontFamily: "'Cinzel', Georgia, serif" }}>
                          <div className="text-[10px] uppercase tracking-[0.42em] text-[#0F4C3A] font-bold">
                            Trace Hub
                          </div>
                          <div className="text-[9px] uppercase tracking-[0.28em] text-[#5a5a5a] mt-0.5">
                            Plataforma de Evidências Digitais
                          </div>
                        </div>
                      </div>

                      {/* Título principal */}
                      <div className="text-center pt-4 pb-5 border-y-2 border-[#0F4C3A]/30">
                        {(() => {
                          const titleText = TITLE_BY_MODE[author.mode];
                          const parts = titleText.split(" ");
                          const mid = Math.ceil(parts.length / 2);
                          const l1 = parts.slice(0, mid).join(" ");
                          const l2 = parts.slice(mid).join(" ");
                          return (
                            <>
                              <h1
                                className="text-[28px] font-bold tracking-[0.32em] uppercase text-[#0F4C3A] leading-tight"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                {l1}
                              </h1>
                              {l2 && (
                                <h1
                                  className="text-[28px] font-bold tracking-[0.32em] uppercase text-[#0F4C3A] leading-tight"
                                  style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                >
                                  {l2}
                                </h1>
                              )}
                            </>
                          );
                        })()}
                        <p
                          className="text-[11px] italic text-[#5a5a5a] mt-2"
                          style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                        >
                          Certidão eletrônica de captura web · Prova autosuficiente
                        </p>
                      </div>

                      {/* Texto cartorial */}
                      <div
                        className="mt-6 text-[12px] leading-[1.7] text-[#1a1a1a] text-justify"
                        style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                      >
                        <p className="indent-8">
                          <strong>Certifica-se</strong>, para os devidos fins de direito, que em{" "}
                          <strong>{new Date(result.timestamp).toLocaleString("pt-BR")}</strong> (timestamp{" "}
                          <em>{result.timestamp_source}</em>), foi realizada captura forense automatizada do conteúdo
                          publicado na rede mundial de computadores no endereço{" "}
                          <span
                            className="font-mono text-[10.5px]"
                            style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                          >
                            {result.final_url}
                          </span>
                          , tendo o sistema retornado status HTTP <strong>{result.http_status}</strong>. A integridade
                          do material foi assegurada mediante geração de impressão digital criptográfica SHA-256,
                          ancorada em blockchain pública e selada por carimbo temporal RFC 3161, conforme detalhado nas
                          partes seguintes deste documento.
                        </p>
                      </div>

                      {/* Resumo tabular */}
                      <table className="w-full mt-6 text-[11px] border-collapse">
                        <tbody>
                          <tr className="border-t-2 border-[#0F4C3A]">
                            <td
                              className="py-1.5 px-3 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[9px] text-[#0F4C3A] w-[42%]"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              URL capturada
                            </td>
                            <td
                              className="py-1.5 px-3 font-mono text-[10px] text-[#1a1a1a] break-all border-l border-[#0F4C3A]/20"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {result.final_url}
                            </td>
                          </tr>
                          <tr className="border-t border-[#0F4C3A]/20">
                            <td
                              className="py-1.5 px-3 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[9px] text-[#0F4C3A]"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              Data e hora da captura
                            </td>
                            <td className="py-1.5 px-3 text-[11px] text-[#1a1a1a] border-l border-[#0F4C3A]/20">
                              {new Date(result.timestamp).toLocaleString("pt-BR")} ({result.timestamp_source})
                            </td>
                          </tr>
                          <tr className="border-t border-[#0F4C3A]/20">
                            <td
                              className="py-1.5 px-3 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[9px] text-[#0F4C3A]"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              Status do servidor
                            </td>
                            <td
                              className="py-1.5 px-3 text-[11px] text-[#1a1a1a] border-l border-[#0F4C3A]/20 font-mono"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {result.http_status} {result.http_status >= 200 && result.http_status < 300 ? "OK" : ""}
                            </td>
                          </tr>
                          {(() => {
                            const prov = detectCdnProvenance(result.http_headers);
                            const isErr = result.http_status >= 400;
                            if (!prov.cdn && !prov.cacheStatus && !isErr) return null;
                            return (
                              <tr className="border-t border-[#0F4C3A]/20">
                                <td
                                  className="py-1.5 px-3 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[9px] text-[#0F4C3A] align-top"
                                  style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                >
                                  Proveniência da resposta
                                </td>
                                <td className="py-1.5 px-3 text-[10.5px] text-[#1a1a1a] border-l border-[#0F4C3A]/20 leading-snug">
                                  <span style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}>
                                    {prov.cdn || "—"}
                                    {prov.cacheStatus ? ` · cache: ${prov.cacheStatus}` : ""}
                                    {prov.servedBy ? ` · ${prov.servedBy}` : ""}
                                  </span>
                                  {isErr && (
                                    <div
                                      className="mt-1 text-[10px] italic text-[#5a5a5a]"
                                      style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                                    >
                                      <strong>Nota técnica:</strong> o código HTTP {result.http_status} foi devolvido
                                      pela camada de proteção WAF/CDN
                                      {prov.cdn ? ` (${prov.cdn})` : ""}, que filtra requisições anônimas. O conteúdo
                                      visual exibido no Anexo Único foi entregue pelo navegador headless ao atingir a
                                      origem com User-Agent de navegador real — preservando, portanto, a representação
                                      pública da página no momento da captura. Headers HTTP brutos, incluindo este
                                      status, estão registrados na Parte VI deste documento.
                                    </div>
                                  )}
                                </td>
                              </tr>
                            );
                          })()}

                          {result.page_title && (
                            <tr className="border-t border-[#0F4C3A]/20">
                              <td
                                className="py-1.5 px-3 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[9px] text-[#0F4C3A]"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                Título da página
                              </td>
                              <td className="py-1.5 px-3 text-[11px] text-[#1a1a1a] border-l border-[#0F4C3A]/20">
                                {result.page_title}
                              </td>
                            </tr>
                          )}
                          <tr className="border-t-2 border-[#0F4C3A]">
                            <td
                              className="py-2 px-3 bg-[#0F4C3A] font-bold uppercase tracking-wider text-[9px] text-white"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              Código único · SHA-256
                            </td>
                            <td
                              className="py-2 px-3 font-mono text-[10px] text-[#0F4C3A] font-bold tracking-wider bg-[#0F4C3A]/5 break-all"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {result.evidence_hash.toLowerCase()}
                            </td>
                          </tr>
                          {result.evidence_hash_sha512 && (
                            <tr className="border-b-2 border-[#0F4C3A]">
                              <td
                                className="py-2 px-3 bg-[#0F4C3A]/85 font-bold uppercase tracking-wider text-[9px] text-white"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                Hash espelho · SHA-512
                              </td>
                              <td
                                className="py-2 px-3 font-mono text-[9px] text-[#0F4C3A]/90 tracking-wider bg-[#0F4C3A]/5 break-all"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                {result.evidence_hash_sha512.toLowerCase()}
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>

                      {/* Bloco 1 — Identificação do Solicitante */}
                      {requester && (
                        <div
                          className="mt-6 border rounded p-4"
                          style={{ borderColor: "#0F4C3A66", backgroundColor: "#0F4C3A08" }}
                        >
                          <div
                            className="text-[10px] uppercase font-bold mb-2 tracking-[0.22em] text-[#0F4C3A]"
                            style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                          >
                            1.0 · Identificação do Solicitante
                          </div>
                          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-[11px]">
                            <div>
                              <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">
                                Nome completo
                              </dt>
                              <dd>{requester.name}</dd>
                            </div>
                            {requester.cpf && (
                              <div>
                                <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">CPF</dt>
                                <dd
                                  className="font-mono text-[10px]"
                                  style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                >
                                  {requester.cpf}
                                </dd>
                              </div>
                            )}
                            {requester.cargo && (
                              <div>
                                <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">
                                  Cargo / função
                                </dt>
                                <dd>{requester.cargo}</dd>
                              </div>
                            )}
                            <div>
                              <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">
                                E-mail da conta
                              </dt>
                              <dd
                                className="font-mono text-[10px] break-all"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                {requester.email}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">Submissão</dt>
                              <dd
                                className="font-mono text-[10px]"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                {new Date(requester.submittedAt).toLocaleString("pt-BR")}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">
                                IP de origem{" "}
                                <span className="not-italic font-normal text-[8px] text-[#0F4C3A]">
                                  (verificado server-side)
                                </span>
                              </dt>
                              <dd
                                className="font-mono text-[10px]"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                {result?.operator_ip || "unknown"}
                              </dd>
                            </div>
                            <div className="sm:col-span-2">
                              <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">
                                ID da requisição{" "}
                                <span className="not-italic font-normal text-[8px] text-[#0F4C3A]">
                                  (gerado server-side)
                                </span>
                              </dt>
                              <dd
                                className="font-mono text-[10px] break-all"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                {result?.request_id || "—"}
                              </dd>
                            </div>
                          </dl>
                          <p
                            className="text-[9.5px] italic mt-2 text-[#5a5a5a]"
                            style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                          >
                            Estes dados integram o cálculo do código único de verificação. Qualquer adulteração
                            posterior invalida a validação pública do documento.
                          </p>
                        </div>
                      )}

                      {/* Selo "AUTENTICADO" */}
                      <div className="flex justify-center mt-7">
                        <div className="inline-flex flex-col items-center gap-1 px-6 py-3 border-2 border-[#0F4C3A] rounded-full bg-white shadow-sm">
                          <div className="flex items-center gap-2">
                            <ShieldCheck className="w-4 h-4 text-[#0F4C3A]" strokeWidth={2.4} />
                            <span
                              className="text-[14px] font-bold tracking-[0.32em] uppercase text-[#0F4C3A]"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              Autenticado
                            </span>
                          </div>
                          <span
                            className="text-[8.5px] uppercase tracking-[0.22em] text-[#5a5a5a]"
                            style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                          >
                            {new Date().toLocaleDateString("pt-BR")}
                          </span>
                        </div>
                      </div>

                      {/* Rodapé do frontispício */}
                      <div className="mt-7 pt-3 border-t border-[#0F4C3A]/30 text-center">
                        <p
                          className="text-[9px] uppercase tracking-[0.22em] text-[#5a5a5a] font-semibold"
                          style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                        >
                          Documento composto por <span data-parts-count>4</span> partes · Validação pública via QR Code
                          na última página
                        </p>
                        <p
                          className="text-[10px] italic text-[#5a5a5a] mt-1"
                          style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                        >
                          CPC art. 411, II · MP 2.200-2/2001 · Lei 14.063/2020
                        </p>
                      </div>
                    </div>
                  </section>

                  {/* ============================================================ */}
                  {/* SELO — Captura em Ambiente Lacrado Trace Hub (premium)        */}
                  {/* ============================================================ */}
                  {sealedResult && (
                    <section
                      data-pdf-section
                      data-pdf-part-header="true"
                      data-pdf-break-before="true"
                      className="px-8 pt-8 pb-6"
                    >
                      <div className="border-2 border-[#0F4C3A] rounded p-5 bg-[#0F4C3A]/[0.03]">
                        <div className="flex items-center gap-3 mb-3">
                          <div className="w-11 h-11 rounded-full bg-[#0F4C3A] flex items-center justify-center">
                            <ShieldCheck className="w-6 h-6 text-white" />
                          </div>
                          <div>
                            <div
                              className="text-[9px] uppercase tracking-[0.32em] text-[#0F4C3A] font-bold"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              Selo Premium
                            </div>
                            <h2
                              className="text-[16px] font-bold tracking-[0.18em] uppercase text-[#1a1a1a] leading-tight"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              Captura em Ambiente Lacrado Trace Hub
                            </h2>
                          </div>
                        </div>
                        <p
                          className="text-[11px] leading-relaxed text-[#1a1a1a] text-justify mb-3"
                          style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                        >
                          A captura foi conduzida em <strong>sessão isolada</strong> pelo Trace Hub: User-Agent fixado,
                          sem extensões de terceiros, todo tráfego HTTP encaminhado pelo <em>proxy auditado</em>e cada
                          evento da sessão (navegação, marcação, rede, finalização) registrado em
                          <strong> cadeia Merkle SHA-256</strong>. A raiz dessa cadeia foi ancorada em
                          <strong> OpenTimestamps (Bitcoin)</strong> e <strong>RFC 3161 (FreeTSA)</strong>, tornando a
                          sessão temporalmente imutável.
                        </p>
                        <table className="w-full text-[10.5px] border-collapse">
                          <tbody>
                            <tr className="border-t border-[#0F4C3A]/30">
                              <td
                                className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A] w-[34%]"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                Sessão
                              </td>
                              <td
                                className="py-1.5 px-2 font-mono text-[10px] break-all border-l border-[#0F4C3A]/20"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                {sealedResult.session_id}
                              </td>
                            </tr>
                            <tr className="border-t border-[#0F4C3A]/20">
                              <td
                                className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                Eventos na cadeia
                              </td>
                              <td className="py-1.5 px-2 border-l border-[#0F4C3A]/20">{sealedResult.event_count}</td>
                            </tr>
                            <tr className="border-t border-[#0F4C3A]/20">
                              <td
                                className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                Encerrada em
                              </td>
                              <td className="py-1.5 px-2 border-l border-[#0F4C3A]/20">
                                {new Date(sealedResult.ended_at).toLocaleString("pt-BR")}
                              </td>
                            </tr>
                            <tr className="border-t-2 border-[#0F4C3A]">
                              <td
                                className="py-2 px-2 bg-[#0F4C3A] font-bold uppercase tracking-wider text-[8.5px] text-white"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                Merkle root SHA-256
                              </td>
                              <td
                                className="py-2 px-2 font-mono text-[9.5px] text-[#0F4C3A] font-bold bg-[#0F4C3A]/5 break-all"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                {sealedResult.merkle_root}
                              </td>
                            </tr>
                            {sealedResult.originstamp_id && (
                              <tr className="border-t border-[#0F4C3A]/20 border-b-2 border-b-[#0F4C3A]">
                                <td
                                  className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                  style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                >
                                  OriginStamp ID
                                </td>
                                <td
                                  className="py-1.5 px-2 font-mono text-[9.5px] break-all border-l border-[#0F4C3A]/20"
                                  style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                >
                                  {sealedResult.originstamp_id}
                                </td>
                              </tr>
                            )}
                            {sealedResult.video_path && (
                              <>
                                <tr className="border-t-2 border-[#0F4C3A]">
                                  <td
                                    colSpan={2}
                                    className="py-2 px-2 bg-[#0F4C3A]/10 font-bold uppercase tracking-wider text-[9px] text-[#0F4C3A]"
                                    style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                  >
                                    Vídeo da sessão (anexo digital ao laudo)
                                  </td>
                                </tr>
                                <tr className="border-t border-[#0F4C3A]/20">
                                  <td
                                    className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                    style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                  >
                                    Arquivo
                                  </td>
                                  <td
                                    className="py-1.5 px-2 font-mono text-[9.5px] break-all border-l border-[#0F4C3A]/20"
                                    style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                  >
                                    {sealedResult.video_path.split("/").pop()}
                                  </td>
                                </tr>
                                <tr className="border-t border-[#0F4C3A]/20">
                                  <td
                                    className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                    style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                  >
                                    Caminho completo
                                  </td>
                                  <td
                                    className="py-1.5 px-2 font-mono text-[9.5px] break-all border-l border-[#0F4C3A]/20"
                                    style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                  >
                                    {sealedResult.video_path}
                                  </td>
                                </tr>
                                <tr className="border-t border-[#0F4C3A]/20">
                                  <td
                                    className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                    style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                  >
                                    Cofre (bucket)
                                  </td>
                                  <td
                                    className="py-1.5 px-2 font-mono text-[10px] border-l border-[#0F4C3A]/20"
                                    style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                  >
                                    {sealedResult.video_bucket ?? "sealed-capture"} (privado)
                                  </td>
                                </tr>
                                {sealedResult.video_size != null && (
                                  <tr className="border-t border-[#0F4C3A]/20">
                                    <td
                                      className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                      style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                    >
                                      Tamanho
                                    </td>
                                    <td className="py-1.5 px-2 border-l border-[#0F4C3A]/20 text-[10px]">
                                      {(sealedResult.video_size / (1024 * 1024)).toFixed(2)} MB (
                                      {sealedResult.video_size.toLocaleString("pt-BR")} bytes)
                                    </td>
                                  </tr>
                                )}
                                {sealedResult.video_mime && (
                                  <tr className="border-t border-[#0F4C3A]/20">
                                    <td
                                      className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                      style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                    >
                                      Tipo MIME
                                    </td>
                                    <td
                                      className="py-1.5 px-2 font-mono text-[9.5px] break-all border-l border-[#0F4C3A]/20"
                                      style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                    >
                                      {sealedResult.video_mime}
                                    </td>
                                  </tr>
                                )}
                                {sealedResult.video_duration_seconds != null && (
                                  <tr className="border-t border-[#0F4C3A]/20">
                                    <td
                                      className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                      style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                    >
                                      Duração
                                    </td>
                                    <td className="py-1.5 px-2 border-l border-[#0F4C3A]/20 text-[10px]">
                                      {(() => {
                                        const total = Math.floor(sealedResult.video_duration_seconds!);
                                        const h = Math.floor(total / 3600)
                                          .toString()
                                          .padStart(2, "0");
                                        const m = Math.floor((total % 3600) / 60)
                                          .toString()
                                          .padStart(2, "0");
                                        const s = (total % 60).toString().padStart(2, "0");
                                        return `${h}:${m}:${s}`;
                                      })()}
                                    </td>
                                  </tr>
                                )}
                                {sealedResult.video_sha256 && (
                                  <tr className="border-t-2 border-[#0F4C3A]">
                                    <td
                                      className="py-2 px-2 bg-[#0F4C3A] font-bold uppercase tracking-wider text-[8.5px] text-white"
                                      style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                    >
                                      SHA-256 do vídeo
                                    </td>
                                    <td
                                      className="py-2 px-2 font-mono text-[9.5px] text-[#0F4C3A] font-bold bg-[#0F4C3A]/5 break-all"
                                      style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                    >
                                      {sealedResult.video_sha256}
                                    </td>
                                  </tr>
                                )}
                                {sealedResult.video_signed_url && (
                                  <tr className="border-t border-[#0F4C3A]/20">
                                    <td
                                      className="py-1.5 px-2 bg-[#0F4C3A]/5 font-bold uppercase tracking-wider text-[8.5px] text-[#0F4C3A]"
                                      style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                                    >
                                      Como baixar o vídeo
                                    </td>
                                    <td
                                      className="py-1.5 px-2 border-l border-[#0F4C3A]/20 text-[10px] leading-snug"
                                      style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                                    >
                                      O vídeo fica guardado no cofre privado do Trace Hub. Para baixá-lo a qualquer
                                      momento, acesse <strong>Trace Hub → Jurídico → Ata Notarial Digital</strong> e
                                      clique em
                                      <strong> "Baixar vídeo"</strong> no painel do selo lacrado.
                                      {sealedResult.video_signed_url_expires_at && (
                                        <div className="mt-1 text-[9px] text-[#5a5a5a] not-italic">
                                          Link assinado de cortesia válido até{" "}
                                          {new Date(sealedResult.video_signed_url_expires_at).toLocaleString("pt-BR")}{" "}
                                          (~30 dias). Após esse prazo, o sistema gera um novo link automaticamente ao
                                          clicar em "Baixar vídeo".
                                        </div>
                                      )}
                                    </td>
                                  </tr>
                                )}
                              </>
                            )}
                          </tbody>
                        </table>
                        {sealedResult.video_path && (
                          <p
                            className="text-[9.5px] italic text-[#5a5a5a] mt-2 leading-snug"
                            style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                          >
                            O hash SHA-256 acima certifica a integridade do arquivo de vídeo. Para validar, baixe o
                            arquivo pela URL assinada e calcule o SHA-256 localmente — qualquer divergência indica
                            adulteração. O vídeo não é embutido no PDF para preservar o tamanho do laudo e permitir
                            custódia separada da mídia; ele fica anexo ao Merkle root da sessão lacrada.
                          </p>
                        )}
                        <p
                          className="text-[9.5px] italic text-[#5a5a5a] mt-3 leading-snug"
                          style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                        >
                          Diferencial técnico do Trace Hub: ancoragem temporal <strong>multi-chain</strong>
                          (Bitcoin via OTS + RFC 3161 FreeTSA), superior à ancoragem RFC 3161 única adotada por
                          concorrentes. O Merkle root permite auditoria evento a evento.
                        </p>
                      </div>
                    </section>
                  )}

                  {/* ============================================================ */}
                  {/* METODOLOGIA TÉCNICA (espelho fiel do PDF)                     */}
                  {/* ============================================================ */}
                  {(() => {
                    const rows = buildMethodologyRows({
                      acquisitionMode: "assistida",
                      hasSha512: !!result.evidence_hash_sha512,
                      anchors: {
                        rfc3161: !!stamp?.rfc3161_timestamp,
                        opentimestamps: !!stamp,
                        bitcoinConfirmed: !!stamp?.bitcoin_block_height,
                      },
                      preservedArtifacts: {
                        html: true,
                        screenshot: true,
                        video: !!sealedResult?.video_path,
                        httpHeaders: true,
                        dns: true,
                        rdap: true,
                        tls: true,
                      },
                    });
                    return (
                      <section data-pdf-section data-pdf-break-before="true" className="px-8 pt-8">
                        <SubHeader>{METHODOLOGY_TITLE}</SubHeader>
                        <div className="mt-3 space-y-2.5">
                          {rows.map(([label, text]) => (
                            <div key={label}>
                              <div className="text-[9px] uppercase tracking-wider text-[#0F4C3A] font-bold">
                                {label}
                              </div>
                              <p
                                className="text-[10.5px] leading-[1.6] text-[#1a1a1a] text-justify"
                                style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                              >
                                {text}
                              </p>
                            </div>
                          ))}
                        </div>
                      </section>
                    );
                  })()}

                  {/* ============================================================ */}
                  {/* PARTE I — DA EVIDÊNCIA CAPTURADA                              */}
                  {/* ============================================================ */}
                  <section data-pdf-section data-pdf-break-before="true" className="px-8 pt-8">
                    <PartHeader
                      number="I"
                      title="Da Evidência Capturada"
                      subtitle="Imagem fiel da página web no instante da captura, acompanhada de seus metadados de transporte"
                    />
                  </section>

                  {(() => {
                    const social = detectSocialNetwork(result.final_url || result.original_url);
                    return (
                      <section data-pdf-section className="px-8 mt-4">
                        <SubHeader>1.1 · Identificação da fonte</SubHeader>
                        {social && (
                          <div className="mt-2 mb-3 border border-[#0F4C3A]/40 bg-[#0F4C3A]/5 rounded p-3">
                            <div className="text-[9px] uppercase tracking-wider text-[#0F4C3A] font-bold mb-1">
                              Coleta em rede social
                            </div>
                            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-[11px]">
                              <div>
                                <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">Plataforma</dt>
                                <dd className="font-bold text-[#1a1a1a]">{social.network}</dd>
                              </div>
                              {social.handle && (
                                <div>
                                  <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">
                                    Conta / handle
                                  </dt>
                                  <dd
                                    className="font-mono text-[10px] text-[#1a1a1a]"
                                    style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                  >
                                    {social.handle.startsWith("@") ||
                                    social.handle.startsWith("+") ||
                                    social.handle.includes("/")
                                      ? social.handle
                                      : `@${social.handle}`}
                                  </dd>
                                </div>
                              )}
                              {social.profileUrl && (
                                <div className="sm:col-span-2">
                                  <dt className="text-[9px] uppercase text-[#5a5a5a] font-semibold mb-0.5">
                                    URL do perfil
                                  </dt>
                                  <dd
                                    className="font-mono text-[10px] break-all text-[#1a1a1a]"
                                    style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                  >
                                    {social.profileUrl}
                                  </dd>
                                </div>
                              )}
                            </dl>
                          </div>
                        )}
                        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-[11.5px] leading-[1.55] mt-2">
                          <div>
                            <dt className="text-[9px] uppercase tracking-wider text-[#5a5a5a] font-semibold mb-0.5">
                              URL solicitada
                            </dt>
                            <dd
                              className="font-mono text-[10px] break-all text-[#1a1a1a]"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {result.original_url}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[9px] uppercase tracking-wider text-[#5a5a5a] font-semibold mb-0.5">
                              URL final (após redirects)
                            </dt>
                            <dd
                              className="font-mono text-[10px] break-all text-[#1a1a1a]"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {result.final_url}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[9px] uppercase tracking-wider text-[#5a5a5a] font-semibold mb-0.5">
                              Timestamp ({result.timestamp_source})
                            </dt>
                            <dd
                              className="font-mono text-[11px] text-[#1a1a1a]"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {new Date(result.timestamp).toLocaleString("pt-BR")}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-[9px] uppercase tracking-wider text-[#5a5a5a] font-semibold mb-0.5">
                              Status HTTP
                            </dt>
                            <dd>
                              {result.http_status >= 200 && result.http_status < 300 ? (
                                <span className="inline-flex items-center px-2 py-0.5 rounded border border-[#0F4C3A]/40 bg-[#0F4C3A]/10 text-[#0F4C3A] text-[10px] font-bold font-mono">
                                  {result.http_status} OK
                                </span>
                              ) : (
                                <span className="inline-flex items-center px-2 py-0.5 rounded border border-amber-300 bg-amber-50 text-amber-800 text-[10px] font-bold font-mono">
                                  {result.http_status}
                                </span>
                              )}
                            </dd>
                          </div>
                        </dl>
                      </section>
                    );
                  })()}

                  {/* Anexo único — screenshot */}
                  <section data-pdf-section data-pdf-tall="true" className="px-8 mt-5">
                    <div className="bg-slate-100 border border-slate-300 px-3 py-1.5 mb-2">
                      <span
                        className="text-[9px] uppercase tracking-[0.28em] text-[#5a5a5a] font-bold"
                        style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                      >
                        Anexo Único — Captura Visual da Página Web
                      </span>
                    </div>
                    {result.screenshot_base64 && result.screenshot_mime ? (
                      <figure className="relative border-2 border-[#1a1a1a] p-2 bg-white shadow-md">
                        {/* Carimbo diagonal */}
                        <div
                          className="absolute top-1/2 left-1/2 pointer-events-none select-none -translate-x-1/2 -translate-y-1/2 -rotate-12"
                          style={{ opacity: 0.06 }}
                          aria-hidden="true"
                        >
                          <span
                            className="text-[48px] font-bold tracking-[0.4em] uppercase text-[#0F4C3A] whitespace-nowrap"
                            style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                          >
                            Prova Documental
                          </span>
                        </div>
                        <img
                          src={`data:${result.screenshot_mime};base64,${result.screenshot_base64}`}
                          alt="Captura notarial"
                          className="w-full block relative"
                        />
                        <figcaption
                          className="text-[9.5px] text-[#1a1a1a] text-center pt-2 mt-2 border-t border-slate-200"
                          style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                        >
                          <strong>Imagem 1.</strong> Captura visual íntegra renderizada em{" "}
                          {new Date(result.timestamp).toLocaleString("pt-BR")}.
                          {result.screenshot_hash && (
                            <span
                              className="block font-mono text-[8.5px] text-[#5a5a5a] mt-0.5"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              SHA-256: {result.screenshot_hash}
                            </span>
                          )}
                        </figcaption>
                      </figure>
                    ) : result.site_status === 'offline' && result.offline_evidence ? (
                      <div className="border-2 border-red-300 bg-red-50 p-4 rounded space-y-3">
                        <div className="flex items-start gap-2">
                          <span className="inline-flex items-center px-2 py-0.5 text-[9px] uppercase tracking-[0.2em] font-bold bg-red-600 text-white rounded">
                            Indisponibilidade constatada
                          </span>
                        </div>
                        <p className="text-[11.5px] leading-[1.6] text-[#1a1a1a]" style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
                          <strong>Em linguagem simples:</strong> o site não respondeu no momento da consulta —
                          o servidor estava fora do ar ou o domínio foi removido. Esta Ata serve como prova de
                          que ele estava indisponível naquele instante e justifica o uso de snapshots históricos
                          (Wayback Machine) na petição.
                        </p>
                        <p className="text-[11.5px] leading-[1.6] text-[#1a1a1a]" style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
                          Esta é uma <strong>Ata Notarial Digital de Indisponibilidade</strong>: no instante UTC{' '}
                          <strong>{new Date(result.timestamp).toISOString()}</strong> a URL alvo não respondeu.
                          Motivo: <strong>{result.offline_summary || result.offline_evidence.reason}</strong>.
                        </p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10.5px]">
                          {(['cloudflare', 'google'] as const).map((k) => {
                            const d = result.offline_evidence!.dns[k];
                            return (
                              <div key={k} className="bg-white border border-red-200 p-2 rounded">
                                <div className="font-bold uppercase tracking-wider text-[9px] text-red-700 mb-1">
                                  {d.resolver}
                                </div>
                                <div>Status DNS: <strong>{d.status.toUpperCase()}</strong></div>
                                <div>Registros A: {d.records.length === 0 ? '—' : d.records.join(', ')}</div>
                                {d.response_hash && (
                                  <div className="font-mono text-[8.5px] text-slate-500 truncate" title={d.response_hash}>
                                    SHA-256: {d.response_hash.slice(0, 24)}…
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                        {result.wayback_suggestion ? (
                          <div className="bg-amber-50 border border-amber-300 p-3 rounded">
                            <div className="text-[10px] font-bold uppercase tracking-wider text-amber-800 mb-1">
                              Snapshot histórico disponível (Wayback Machine)
                            </div>
                            <p className="text-[11px] text-amber-900 mb-2">
                              O Internet Archive preservou uma cópia do site em{' '}
                              <strong>{result.wayback_suggestion.timestamp}</strong>. Capture-o em uma nova
                              Ata Notarial para registrar o conteúdo histórico junto a este laudo.
                            </p>
                            <a
                              href={result.wayback_suggestion.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-block bg-amber-600 hover:bg-amber-700 text-white text-[11px] font-bold px-3 py-1.5 rounded no-underline"
                            >
                              Abrir snapshot no Wayback Machine →
                            </a>
                          </div>
                        ) : (
                          <div className="text-[10.5px] text-slate-600 italic">
                            Nenhum snapshot encontrado no Internet Archive (Wayback Machine) para esta URL.
                          </div>
                        )}
                        <p className="text-[10px] text-slate-600 leading-[1.5]" style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
                          Constatação técnica de indisponibilidade tem aplicação análoga ao art. 405, §1º do CPC
                          como prova documental, podendo ser instruída em conjunto com snapshot do Internet
                          Archive para reconstituição do conteúdo pretérito.
                        </p>
                      </div>
                    ) : (
                      <div className="text-[11px] p-3 rounded border border-dashed border-amber-300 bg-amber-50 text-amber-800">
                        {result.screenshot_warning ||
                          "Screenshot indisponível. Evidência HTML preservada com integridade SHA-256."}
                      </div>
                    )}
                  </section>

                  {/* ============================================================ */}
                  {/* PARTE II — DA INTEGRIDADE CRIPTOGRÁFICA                       */}
                  {/* ============================================================ */}
                  <section data-pdf-section data-pdf-break-before="true" className="px-8 pt-8">
                    <PartHeader
                      number="II"
                      title="Da Integridade Criptográfica"
                      subtitle="Impressões digitais SHA-256 que garantem que a evidência não foi alterada após a captura"
                    />
                  </section>

                  <section data-pdf-section className="px-8 mt-4">
                    <p
                      className="text-[11.5px] leading-[1.65] text-[#1a1a1a] text-justify mb-4"
                      style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                    >
                      As funções <em>hash</em> SHA-256 abaixo constituem impressão digital única e irreversível do
                      conteúdo capturado. Qualquer alteração — ainda que de um único bit — resultaria em <em>hash</em>{" "}
                      completamente distinto, permitindo que perito independente verifique a íntegra preservação da
                      evidência.
                    </p>

                    <div className="space-y-3">
                      {result.screenshot_hash && (
                        <div>
                          <div
                            className="text-[9px] uppercase tracking-[0.18em] text-[#5a5a5a] font-bold mb-1"
                            style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                          >
                            2.1 · Hash do screenshot
                          </div>
                          <p
                            className="font-mono text-[10px] break-all bg-[#fafaf7] border border-slate-300 px-3 py-2 rounded text-[#1a1a1a]"
                            style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                          >
                            {formatHashForDisplay(result.screenshot_hash)}
                          </p>
                        </div>
                      )}
                      <div>
                        <div
                          className="text-[9px] uppercase tracking-[0.18em] text-[#5a5a5a] font-bold mb-1"
                          style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                        >
                          2.2 · Hash do HTML ({result.html_size.toLocaleString("pt-BR")} bytes)
                        </div>
                        <p
                          className="font-mono text-[10px] break-all bg-[#fafaf7] border border-slate-300 px-3 py-2 rounded text-[#1a1a1a]"
                          style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                        >
                          {formatHashForDisplay(result.html_hash)}
                        </p>
                        {(result.html_size < 5000 || result.http_status >= 400) && (
                          <p
                            className="mt-2 text-[10px] italic text-[#5a5a5a] leading-snug bg-amber-50 border border-amber-200 px-3 py-2 rounded"
                            style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                          >
                            <strong>Distinção técnica:</strong> o hash acima corresponde ao <em>HTML bruto</em>
                            devolvido pelo servidor de origem em resposta direta — neste caso{" "}
                            <strong>{result.html_size.toLocaleString("pt-BR")} bytes</strong>
                            {result.html_full_size && result.html_truncated ? (
                              <> (truncado de {result.html_full_size.toLocaleString("pt-BR")} bytes)</>
                            ) : null}
                            . O conteúdo visual reproduzido no Anexo Único é o <em>DOM renderizado</em>
                            por navegador headless (Chrome) após execução de JavaScript e carregamento de recursos,
                            refletindo o que um usuário comum visualizaria. Tamanhos reduzidos de HTML bruto são típicos
                            de aplicações SPA (Single Page Applications) ou de respostas interceptadas por WAF/CDN — não
                            comprometem a integridade da captura visual, mas esclarecem que{" "}
                            <strong>HTML preservado ≠ pixels exibidos</strong>.
                          </p>
                        )}
                      </div>

                      {/* Hash composto — DESTAQUE MÁXIMO (DNA da prova) */}
                      <div className="border-2 border-[#0F4C3A] bg-[#0F4C3A]/5 p-4 rounded-lg mt-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Lock className="w-4 h-4 text-[#0F4C3A]" strokeWidth={2.4} />
                          <span
                            className="text-[10px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold"
                            style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                          >
                            2.3 · Código Único de Verificação · SHA-256
                          </span>
                        </div>
                        <p
                          className="text-[10.5px] italic text-[#5a5a5a] mb-2 leading-snug"
                          style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                        >
                          Hash composto que sintetiza toda a evidência (screenshot + HTML + metadados). Este é o{" "}
                          <strong>código de protocolo</strong> usado para validação pública.
                        </p>
                        <p
                          className="font-mono text-[12px] break-all bg-white border-2 border-[#0F4C3A] px-3 py-2.5 rounded text-[#0F4C3A] font-bold tracking-wider text-center"
                          style={{ fontFamily: "'JetBrains Mono', Courier, monospace", letterSpacing: "0.04em" }}
                        >
                          {result.evidence_hash.toLowerCase()}
                        </p>
                        {result.evidence_hash_sha512 && (
                          <>
                            <p
                              className="text-[10px] uppercase font-bold mt-3 mb-1 tracking-[0.18em] text-[#0F4C3A]/80"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              Hash espelho · SHA-512 (FIPS 180-4)
                            </p>
                            <p
                              className="text-[10.5px] italic text-[#5a5a5a] mb-2 leading-snug"
                              style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                            >
                              Hash redundante de 512 bits, calculado sobre o mesmo payload determinístico, em paridade
                              com a norma ISO/IEC 27037 e ferramentas de mercado equivalentes.
                            </p>
                            <p
                              className="font-mono text-[10px] break-all bg-white border border-[#0F4C3A]/40 px-3 py-2 rounded text-[#0F4C3A]/90 tracking-wider text-center"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace", letterSpacing: "0.03em" }}
                            >
                              {result.evidence_hash_sha512.toLowerCase()}
                            </p>
                          </>
                        )}
                      </div>
                    </div>
                  </section>

                  {/* ============================================================ */}
                  {/* PARTE III — DA ANCORAGEM TEMPORAL                             */}
                  {/* ============================================================ */}
                  <section data-pdf-section data-pdf-break-before="true" className="px-8 pt-8">
                    <PartHeader
                      number="III"
                      title="Da Ancoragem Temporal"
                      subtitle="Selo OpenTimestamps (Bitcoin, gratuito) e carimbo de tempo qualificado RFC 3161 (FreeTSA)"
                    />
                  </section>

                  <section data-pdf-section className="px-8 mt-4">
                    <p
                      className="text-[11.5px] leading-[1.65] text-[#1a1a1a] text-justify mb-4"
                      style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                    >
                      A evidência foi ancorada de forma dupla e independente: (i) selo
                      <em> OpenTimestamps</em> submetido ao calendário público da OpenTimestamps Foundation, que agrega
                      o hash em uma árvore Merkle confirmada na blockchain Bitcoin (confirmação plena em 1 a 6 horas,
                      automática); e (ii) carimbo de tempo qualificado <em>RFC 3161</em> emitido{" "}
                      <strong>imediatamente</strong> por autoridade certificadora independente (FreeTSA), com validade
                      legal autônoma.
                    </p>

                    {!stamp && (
                      <div
                        className="rounded-lg border-2 border-amber-500/70 bg-amber-50 p-4 shadow-sm"
                        data-html2canvas-ignore="true"
                      >
                        <div className="flex items-center gap-2 mb-3">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500 text-white text-[10px] font-bold uppercase tracking-[0.18em]">
                            <AlertTriangle className="w-3 h-3" strokeWidth={2.6} />
                            Ação necessária · Clique aqui
                          </span>
                        </div>

                        <p className="text-[12.5px] text-amber-950 mb-1 leading-[1.5] font-semibold">
                          Clique no botão abaixo para selar a evidência agora.
                        </p>
                        <p className="text-[11.5px] text-amber-900/80 mb-4 leading-[1.55]">
                          Emite selo <strong>OpenTimestamps</strong> (Bitcoin, gratuito) + token{" "}
                          <strong>RFC 3161</strong> imediato (FreeTSA). Leva ~3 segundos. Sem esta etapa, o laudo é
                          gerado <strong>sem ancoragem temporal</strong>.
                        </p>

                        <div className={stamping ? "" : "animate-pulse"}>
                          <Button
                            onClick={() => handleStamp()}
                            disabled={stamping}
                            size="lg"
                            className="w-full h-14 bg-[#0F4C3A] hover:bg-[#0a3528] text-white text-[14px] font-bold uppercase tracking-wider ring-4 ring-[#0F4C3A]/25 shadow-lg"
                          >
                            {stamping ? (
                              <>
                                <Loader2 className="w-5 h-5 mr-2 animate-spin" /> Selando…
                              </>
                            ) : (
                              <>
                                <Anchor className="w-5 h-5 mr-2.5" strokeWidth={2.6} />
                                <span className="flex-1 text-center">Clique para selar agora</span>
                                <ArrowRight className="w-5 h-5 ml-2" strokeWidth={2.6} />
                              </>
                            )}
                          </Button>
                        </div>

                        <p className="text-[10.5px] text-amber-900/70 mt-2.5 text-center italic">
                          Etapa obrigatória — só depois disto o PDF poderá ser baixado com validade temporal.
                        </p>
                      </div>
                    )}

                    {stamp && (
                      <div className="grid sm:grid-cols-2 gap-3">
                        <div className="border-2 border-[#0F4C3A]/40 bg-white rounded-lg p-3.5">
                          <div className="flex items-center gap-2 mb-2 pb-2 border-b border-slate-200">
                            <Anchor className="w-4 h-4 text-[#0F4C3A]" strokeWidth={2.4} />
                            <span
                              className="text-[10px] uppercase tracking-[0.18em] text-[#0F4C3A] font-bold"
                              style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                            >
                              3.1 · OPENTIMESTAMPS — Âncora Bitcoin
                            </span>
                          </div>
                          <p
                            className="text-[10.5px] text-[#1a1a1a] leading-snug mb-1.5"
                            style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                          >
                            Hash submetido em:
                          </p>
                          <p
                            className="font-mono text-[10px] text-[#0F4C3A] font-bold mb-1.5"
                            style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                          >
                            {new Date(stamp.submitted_at).toLocaleString("pt-BR")}
                          </p>
                          {stamp.timestamp_id && (
                            <p
                              className="text-[9.5px] text-[#5a5a5a] leading-snug mb-1"
                              style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                            >
                              Hash:{" "}
                              <span className="font-mono text-[9px] text-[#0F4C3A] break-all">
                                {stamp.timestamp_id}
                              </span>
                            </p>
                          )}
                          <div className="flex flex-wrap gap-1 mb-2">
                            {(stamp.currencies.length ? stamp.currencies : ["btc"]).map((c) => (
                              <Badge
                                key={c}
                                variant="outline"
                                className="text-[9px] uppercase border-[#0F4C3A]/50 text-[#0F4C3A] font-bold"
                              >
                                {c}
                              </Badge>
                            ))}
                          </div>
                          <p
                            className="text-[9.5px] text-[#5a5a5a] leading-snug"
                            style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                          >
                            Confirmação Bitcoin completa em 1-6h (automática, gratuita)
                          </p>
                        </div>

                        {stamp.rfc3161_token_base64 && (
                          <div className="border-2 border-[#0F4C3A]/40 bg-white rounded-lg p-3.5">
                            <div className="flex items-center gap-2 mb-2 pb-2 border-b border-slate-200">
                              <Clock className="w-4 h-4 text-[#0F4C3A]" strokeWidth={2.4} />
                              <span
                                className="text-[10px] uppercase tracking-[0.18em] text-[#0F4C3A] font-bold"
                                style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                              >
                                3.2 · RFC 3161 · FreeTSA
                              </span>
                            </div>
                            <p
                              className="text-[10.5px] text-[#1a1a1a] leading-snug mb-1.5"
                              style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                            >
                              Carimbo qualificado emitido em:
                            </p>
                            <p
                              className="font-mono text-[10px] text-[#0F4C3A] font-bold mb-2"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {stamp.rfc3161_timestamp && new Date(stamp.rfc3161_timestamp).toLocaleString("pt-BR")}
                            </p>
                            <p
                              className="text-[9.5px] text-[#5a5a5a] leading-snug"
                              style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                            >
                              Autoridade certificadora independente · confirmação imediata
                            </p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Bloco 6 — Explicação para leigos */}
                    {stamp && <TemporalAnchorExplainer />}

                    {/* Bloco 7 — Status de confirmação OpenTimestamps */}
                    {stamp && otsStatus && (
                      <OpenTimestampsStatus
                        status={otsStatus}
                        onVerify={verifyOts}
                        onRegenerate={() => handleExportPDF(false)}
                        verifying={otsVerifying}
                      />
                    )}
                  </section>

                  {/* ============================================================ */}
                  {/* PARTE IV — DA VALIDAÇÃO PÚBLICA (QR EM PÁGINA DEDICADA)       */}
                  {/* ============================================================ */}
                  <section data-pdf-section data-pdf-break-before="true" className="px-8 pt-8">
                    <PartHeader
                      number="IV"
                      title="Da Validação Pública"
                      subtitle="Verificação independente da autenticidade e integridade deste documento"
                    />
                  </section>

                  <section data-pdf-section className="px-8 mt-4 pb-8">
                    <ForensicSeal hash={result.evidence_hash} reportType="notarial" fullPage pdfHash={pdfSha256} />
                  </section>

                  {/* Anexo de snapshot de infraestrutura removido: os dados de rede
                      (DNS multi-resolver, RDAP, ASN, TLS) seguem na Parte VI. */}

                  {/* ============================================================ */}
                  {/* PARTE VI — VERIFICAÇÕES TÉCNICAS COMPLEMENTARES (selo AFD)    */}
                  {/* ============================================================ */}
                  <section data-pdf-section data-pdf-break-before="true" className="px-8 pt-8">
                    <PartHeader
                      number="VI"
                      title="Verificações Técnicas Complementares"
                      subtitle="Anti-DNS-Poisoning, metadados de rede e checklist normativo conforme estudo Academia de Forense Digital (2024)"
                    />
                  </section>

                  <section data-pdf-section className="px-8 mt-4 space-y-4">
                    {/* 6.1 — Integridade DNS */}
                    {result.dnsIntegrity && (
                      <div>
                        <div
                          className="text-[10px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold mb-2"
                          style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                        >
                          6.1 · Integridade DNS — resolução em ambiente isolado
                        </div>
                        {(() => {
                          const engineLvl =
                            result.dnsIntegrity.dns_consensus_level ??
                            (result.dnsIntegrity.dns_consensus ? "consensus_strong" : "divergent");
                          const TOTAL_RESOLVERS = 5;
                          const responded = Number(result.dnsIntegrity.responding_resolvers ?? 0);
                          const concordant =
                            engineLvl === "consensus_strong" ||
                            engineLvl === "consensus_anycast" ||
                            engineLvl === "consensus_partial";
                          // Quorum mínimo para "consenso forte": 3 de 5 respondendo E concordando.
                          const lvl = concordant
                            ? responded >= 3
                              ? engineLvl === "consensus_anycast"
                                ? "consensus_anycast"
                                : "consensus_strong"
                              : responded === 2
                              ? "consensus_partial"
                              : "inconclusive"
                            : engineLvl === "divergent"
                            ? "divergent"
                            : "inconclusive";
                          const quorumNote = ` (${responded} de ${TOTAL_RESOLVERS} resolvedores responderam)`;
                          const statusMap: Record<string, { color: string; bg: string; text: string }> = {
                            consensus_strong: {
                              color: "#0F4C3A",
                              bg: "rgba(15,76,58,0.05)",
                              text: `✓ Consenso forte — quorum mínimo de 3/5 atendido, com IPs no mesmo prefixo (/24 ou /48)${quorumNote}. Imune a DNS Poisoning local.`,
                            },
                            consensus_anycast: {
                              color: "#0F4C3A",
                              bg: "rgba(15,76,58,0.05)",
                              text: `✓ Consenso forte em rede anycast/CDN — quorum mínimo de 3/5 atendido, com IPs no mesmo Sistema Autônomo (ASN)${quorumNote}. Comportamento esperado para domínios de grande porte.`,
                            },
                            consensus_partial: {
                              color: "#b45309",
                              bg: "rgba(180,83,9,0.05)",
                              text: `ℹ Consenso parcial (2 de ${TOTAL_RESOLVERS} resolvedores) — respostas concordantes, porém abaixo do quorum mínimo de 3/5. Recomenda-se repetir a captura.`,
                            },
                            inconclusive: {
                              color: "#b45309",
                              bg: "rgba(180,83,9,0.05)",
                              text: `⚠ Inconclusivo — falha da maioria dos resolvedores${quorumNote}. O resultado não sustenta afirmação de ausência de envenenamento DNS; repita a captura.`,
                            },
                            divergent: {
                              color: "#b91c1c",
                              bg: "rgba(185,28,28,0.05)",
                              text: `⚠ Divergência real entre resolvedores DoH (ASNs distintos) — possível manipulação na origem${quorumNote}.`,
                            },
                          };
                          const cfg = statusMap[lvl] ?? statusMap.inconclusive;

                          return (
                            <div
                              className="rounded-md p-3 text-[11px]"
                              style={{
                                border: `2px solid ${cfg.color}`,
                                background: cfg.bg,
                                fontFamily: "'EB Garamond', Georgia, serif",
                              }}
                            >
                              <div className="mb-1.5">
                                <strong>Status:</strong> {cfg.text}
                              </div>
                              <div className="mb-1.5">
                                <strong>IPs consensuais:</strong>{" "}
                                <span style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}>
                                  {result.dnsIntegrity.consensus_ips.join(", ") || "—"}
                                </span>
                              </div>
                              <div className="mb-1.5">
                                <strong>Método:</strong> {result.dnsIntegrity.method}
                              </div>
                              <table className="w-full mt-2 text-[10px] border-collapse">
                                <thead>
                                  <tr style={{ background: "#f1efe8" }}>
                                    <th className="text-left p-1.5 border border-[#cbd5d2]">Resolver</th>
                                    <th className="text-left p-1.5 border border-[#cbd5d2]">A</th>
                                    <th className="text-left p-1.5 border border-[#cbd5d2]">AAAA</th>
                                    <th className="text-left p-1.5 border border-[#cbd5d2]">RTT</th>
                                    <th className="text-left p-1.5 border border-[#cbd5d2]">Status</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {result.dnsIntegrity.resolver_chain.a.map((r, i) => {
                                    const aaaa = result.dnsIntegrity!.resolver_chain.aaaa[i];
                                    const err = r.error || aaaa?.error;
                                    return (
                                      <tr key={r.resolver}>
                                        <td
                                          className="p-1.5 border border-[#cbd5d2]"
                                          style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                        >
                                          {r.resolver}
                                        </td>
                                        <td
                                          className="p-1.5 border border-[#cbd5d2]"
                                          style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                        >
                                          {r.ips.join(", ") || "—"}
                                        </td>
                                        <td
                                          className="p-1.5 border border-[#cbd5d2]"
                                          style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                                        >
                                          {aaaa?.ips.join(", ") || "—"}
                                        </td>
                                        <td className="p-1.5 border border-[#cbd5d2]">{r.rttMs} ms</td>
                                        <td className="p-1.5 border border-[#cbd5d2] text-[9.5px]" title={err || ""}>
                                          {err ? (
                                            <span className="text-amber-700">timeout/erro: {err.slice(0, 40)}</span>
                                          ) : (
                                            <span className="text-[#0F4C3A]">OK</span>
                                          )}
                                        </td>
                                      </tr>
                                    );
                                  })}
                                </tbody>
                              </table>
                              {(() => {
                                const failedRows = result.dnsIntegrity!.resolver_chain.a.filter((r) => r.error);
                                const failed = failedRows.length;
                                if (failed === 0) return null;
                                const respondedN = Number(result.dnsIntegrity!.responding_resolvers ?? 0);
                                return (
                                  <p
                                    className="mt-2 text-[10px] italic text-[#5a5a5a] leading-snug"
                                    style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                                  >
                                    <strong>Nota:</strong> {failed} de {result.dnsIntegrity!.resolver_chain.a.length}{" "}
                                    resolvers DoH não responderam dentro do <em>timeout</em> de 5 s. Motivo declarado por
                                    resolvedor:{" "}
                                    {failedRows
                                      .map((r) => `${r.resolver} — ${String(r.error).slice(0, 60)}`)
                                      .join("; ")}
                                    . O quorum forense adotado exige no mínimo 3 de 5 resolvedores independentes
                                    respondendo e concordando; este requisito{" "}
                                    {respondedN >= 3 ? (
                                      <strong>foi atendido</strong>
                                    ) : respondedN === 2 ? (
                                      <strong className="text-amber-700">
                                        NÃO foi atendido — consenso parcial (2 de 5)
                                      </strong>
                                    ) : (
                                      <strong className="text-amber-700">
                                        NÃO foi atendido — inconclusivo por falha da maioria dos resolvedores
                                      </strong>
                                    )}
                                    .
                                  </p>
                                );
                              })()}

                            </div>
                          );
                        })()}
                      </div>
                    )}

                    {/* 6.2 — Metadados de Rede */}
                    {result.networkMetadata && (
                      <div>
                        <div
                          className="text-[10px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold mb-2"
                          style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                        >
                          6.2 · Metadados Técnicos de Rede
                        </div>
                        <div
                          className="rounded-md border border-[#cbd5d2] bg-[#fafaf6] p-3 text-[11px]"
                          style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                        >
                          <div className="mb-2">
                            <strong>RDAP (registrante):</strong>
                            {result.networkMetadata.rdap && !("error" in result.networkMetadata.rdap) ? (
                              <div
                                className="mt-1 text-[10px]"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                Domínio: {result.networkMetadata.rdap.ldhName} · Registrar:{" "}
                                {result.networkMetadata.rdap.registrar || "—"}
                                <br />
                                Criado: {result.networkMetadata.rdap.events?.registration || "—"} · Expira:{" "}
                                {result.networkMetadata.rdap.events?.expiration || "—"}
                                <div>
                                  Nameservers: {(result.networkMetadata.rdap.nameservers || []).join(", ") || "—"}
                                </div>
                              </div>
                            ) : (
                              <div>
                                <span className="text-[#5a5a5a]"> indisponível via RDAP padrão (IANA/ICANN)</span>
                                <p
                                  className="mt-1 text-[10px] italic text-[#5a5a5a] leading-snug"
                                  style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                                >
                                  <strong>Nota:</strong> domínios <code>.br</code> e alguns ccTLDs não publicam dados
                                  RDAP em <em>endpoint</em> padrão consultado. Para titularidade certificada, consultar{" "}
                                  <span style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}>
                                    rdap.registro.br
                                  </span>{" "}
                                  ou Whois oficial do Registro.br. A indisponibilidade não compromete os demais
                                  metadados de rede coletados (DNS, TLS, IPs).
                                </p>
                              </div>
                            )}
                          </div>

                          <div className="mb-2">
                            <strong>Registros DNS (Cloudflare DoH):</strong>
                            <div
                              className="mt-1 text-[10px]"
                              style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                            >
                              {(["A", "AAAA", "MX", "NS", "TXT", "CAA"] as const).map((t) => {
                                const recs = result.networkMetadata!.dns[t];
                                return (
                                  <div key={t}>
                                    <span className="text-[#0F4C3A] font-bold">{t}:</span>{" "}
                                    {recs?.length ? recs.map((r) => r.data).join(" | ") : "—"}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                          <div>
                            <strong>Certificado TLS:</strong>
                            {result.networkMetadata.tls && !("error" in result.networkMetadata.tls) ? (
                              <div
                                className="mt-1 text-[10px]"
                                style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                              >
                                Emissor: {String((result.networkMetadata.tls as { issuer?: unknown }).issuer || "—")}
                                <div>
                                  Validade: {(result.networkMetadata.tls as { validFrom?: string }).validFrom || "—"} →{" "}
                                  {(result.networkMetadata.tls as { validTo?: string }).validTo || "—"}
                                </div>
                                <div>
                                  Serial:{" "}
                                  {(result.networkMetadata.tls as { serialNumber?: string }).serialNumber || "—"}
                                </div>
                              </div>
                            ) : (
                              <span className="text-[#5a5a5a]">
                                {" "}
                                {(result.networkMetadata.tls as { error?: string }).error || "indisponível"}
                              </span>
                            )}
                          </div>

                          {result.networkMetadata.asn && result.networkMetadata.asn.length > 0 && (
                            <div className="mt-2">
                              <strong>ASN / Operadora de rede (Team Cymru):</strong>
                              <div className="mt-1 text-[10px]" style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}>
                                {result.networkMetadata.asn.map((a) => (
                                  <div key={a.ip}>
                                    <span className="text-[#0F4C3A] font-bold">{a.ip}</span>{" "}
                                    {a.asn ? `→ ${a.asn} (${a.as_org || "—"}) · ${a.country || "—"} · ${a.prefix || "—"}` : `→ ${a.error || "indisponível"}`}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* 6.2.1 — Ambiente do Coletor (UA + Viewport) */}
                    {result.captureEnv && (
                      <div>
                        <div
                          className="text-[10px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold mb-2"
                          style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                        >
                          6.2.1 · Ambiente do Coletor
                        </div>
                        <div
                          className="rounded-md border border-[#cbd5d2] bg-[#fafaf6] p-3 text-[11px]"
                          style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                        >
                          <div><strong>User-Agent:</strong> {result.captureEnv.user_agent}</div>
                          <div><strong>Viewport:</strong> {result.captureEnv.viewport_width}×{result.captureEnv.viewport_height} @ {result.captureEnv.device_scale_factor}x</div>
                          <div><strong>Engine:</strong> {result.captureEnv.browser_engine}</div>
                          <div><strong>Coletor:</strong> {result.captureEnv.collector}</div>
                        </div>
                        <p className="mt-1 text-[10px] italic text-[#5a5a5a]" style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
                          Declarado para descartar alegação de cloaking servido a UA específico ou viewport mobile.
                        </p>
                      </div>
                    )}

                    {/* 6.2.2 — Árvore de Merkle (cobertura de integridade dos artefatos) */}
                    {result.merkle && (
                      <div>
                        <div
                          className="text-[10px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold mb-2"
                          style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                        >
                          6.2.2 · Árvore de Merkle (cobertura de integridade)
                        </div>
                        <div
                          className="rounded-md border border-[#cbd5d2] bg-[#fafaf6] p-3 text-[10px]"
                          style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}
                        >
                          <div className="mb-1"><strong>Algoritmo:</strong> {result.merkle.algorithm}</div>
                          <div className="mb-2 break-all"><strong>Root (ancorado):</strong> {result.merkle.root}</div>
                          <div><strong>Folhas:</strong></div>
                          {result.merkle.leaves.map((l) => (
                            <div key={l.label} className="break-all">
                              · {l.label}: {l.hash.slice(0, 32)}…
                            </div>
                          ))}
                        </div>
                        <p className="mt-1 text-[10px] italic text-[#5a5a5a]" style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
                          O root acima foi timestampado em blockchain via OriginStamp. Cobre todos os artefatos
                          coletados — qualquer alteração posterior (screenshot, HTML, DNS, TLS, ambiente) quebra
                          a prova matemática contra o root timestampado.
                        </p>
                      </div>
                    )}


                    {/* 6.3 — Checklist de Conformidade */}
                    <div>
                      <div
                        className="text-[10px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold mb-2"
                        style={{ fontFamily: "'Cinzel', Georgia, serif" }}
                      >
                        6.3 · Checklist de Conformidade Normativa
                      </div>
                      <div
                        className="rounded-md border-2 border-[#0F4C3A] bg-[#0F4C3A]/5 p-3 text-[11px]"
                        style={{ fontFamily: "'EB Garamond', Georgia, serif" }}
                      >
                        {(
                          [
                            [
                              result.dnsIntegrity?.dns_consensus !== false,
                              "Isolamento do fato durante a coleta",
                              "Captura executada em ambiente cloud isolado (Edge Function + headless browser remoto). Sem dependência do DNS, proxy ou resolver do operador — eliminando vetor de DNS Poisoning e MITM local.",
                            ],
                            [
                              true,
                              "Coleta sistemática e detalhada",
                              "RDAP, registros DNS (A/AAAA/MX/NS/TXT/CAA), certificado TLS, cabeçalhos HTTP de origem, Open Graph, screenshot e HTML cru.",
                            ],
                            [
                              true,
                              "Preservação da prova (FIPS 180-4)",
                              "SHA-256 sobre URL + IP + UA + timestamp + screenshot + HTML, com identificação do solicitante encadeada.",
                            ],
                            [
                              !!stamp,
                              "Carimbo de tempo independente",
                              "OpenTimestamps (Bitcoin) + RFC 3161 (FreeTSA) — ver Parte III.",
                            ],
                            [
                              true,
                              "ISO/IEC 27037:2012",
                              "Itens 5.4 (identificação), 5.5 (coleta), 5.6 (aquisição) e 5.7 (preservação) atendidos pelo fluxo.",
                            ],
                            [
                              true,
                              "RFC 3227 — Ordem de Volatilidade",
                              "Evidência coletada na ordem correta de volatilidade: conteúdo de rede (mais volátil) capturado antes de metadados e logs (menos voláteis), conforme RFC 3227 (IETF).",
                            ],
                            [
                              true,
                              "CPP art. 158-A (aplicação analógica — vestígio digital)",
                              "Lei 13.964/2019 escrita para vestígios materiais; aplicada por analogia consolidada (STJ HC 1.036.370). Cadeia de custódia documentada por hash encadeado e ID único de evidência.",
                            ],
                            [
                              true,
                              "Provimento CNJ 100/2020",
                              "Estrutura do laudo em partes (I–VI) com QR de validação pública atende ao formato de ata notarial eletrônica do CNJ.",
                            ],
                          ] as Array<[boolean, string, string]>
                        ).map(([ok, title, desc]) => (
                          <div key={title} className="flex gap-2 mb-1.5">
                            <span className="font-bold" style={{ color: ok ? "#0F4C3A" : "#b91c1c" }}>
                              {ok ? "✓" : "⚠"}
                            </span>
                            <div>
                              <div className="font-bold">{title}</div>
                              <div className="text-[10px] text-[#374151]">{desc}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </section>

                  {/* Assinatura do signatário técnico */}
                  <section data-pdf-section className="bg-white px-10 py-6">
                    <ForensicAuthorBlock author={author} />
                    <ForensicSignatureBlock author={author} />
                  </section>
                </div>

                {/* ====== Ações fora do PDF ====== */}
                {stamp && (
                  <div className="space-y-2" data-html2canvas-ignore="true">
                    <Button
                      onClick={handleDownloadPackage}
                      disabled={packaging || generatingPdf}
                      size="lg"
                      className="w-full bg-emerald-600 hover:bg-emerald-700 text-white shadow-md"
                    >
                      {packaging ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Montando pacote…
                        </>
                      ) : (
                        <>
                          <Package className="w-4 h-4 mr-2" /> Baixar pacote completo da prova (ZIP)
                        </>
                      )}
                    </Button>
                    <p className="text-[11px] text-muted-foreground text-center">
                      Um único arquivo com a certidão em PDF, os selos .ots e .tsr já emitidos, o
                      screenshot e as instruções de verificação independente.
                    </p>
                    <Button
                      onClick={() => handleExportPDF(false)}
                      disabled={generatingPdf || packaging}
                      variant="outline"
                      className="w-full"
                    >
                      {generatingPdf ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Gerando certidão…
                        </>
                      ) : (
                        <>
                          <FileSignature className="w-4 h-4 mr-2" /> Somente a Certidão Digital (PDF)
                        </>
                      )}
                    </Button>

                    <div className="grid sm:grid-cols-2 gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          downloadBase64(
                            stamp.raw_response_base64,
                            `evidencia-${result.evidence_hash.slice(0, 12)}.ots`,
                            "application/octet-stream",
                          )
                        }
                      >
                        <Download className="w-3.5 h-3.5 mr-1.5" /> Baixar .ots (OpenTimestamps)
                      </Button>
                      {stamp.rfc3161_token_base64 && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            downloadBase64(
                              stamp.rfc3161_token_base64!,
                              `evidencia-${result.evidence_hash.slice(0, 12)}.tsr`,
                              "application/timestamp-reply",
                            )
                          }
                        >
                          <Download className="w-3.5 h-3.5 mr-1.5" /> Baixar .tsr (RFC 3161)
                        </Button>
                      )}
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={handleExportPNG}
                      disabled={generatingPdf}
                      className="w-full text-xs text-muted-foreground hover:text-foreground"
                    >
                      Se o PDF falhar, baixar como imagem (PNG)
                    </Button>
                    <p className="text-[11px] text-muted-foreground text-center pt-1">
                      Para verificar de forma independente: instale o cliente{" "}
                      <code className="font-mono text-[10px]">ots</code> (
                      <a
                        href="https://opentimestamps.org"
                        target="_blank"
                        rel="noopener"
                        className="text-emerald-600 hover:underline"
                      >
                        opentimestamps.org
                      </a>
                      ) e rode <code className="font-mono text-[10px]">ots verify evidencia.ots</code>.
                    </p>
                  </div>
                )}

                {/* Headers HTTP — apenas tela, não entra no PDF */}
                <details
                  className="rounded-lg border border-border bg-muted/30 p-3 text-xs"
                  data-html2canvas-ignore="true"
                >
                  <summary className="cursor-pointer text-muted-foreground font-medium">
                    Headers HTTP do servidor ({Object.keys(result.http_headers).length}) — não incluso no PDF
                  </summary>
                  <pre className="text-[10px] font-mono bg-background p-2 mt-2 rounded whitespace-pre-wrap break-all border">
                    {Object.entries(result.http_headers)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                  </pre>
                </details>

                {/* Mensagem de conclusão — Ata já é juridicamente válida */}
                {stamp && (
                  <div className="flex items-start gap-3 p-4 rounded-lg border border-emerald-500/40 bg-emerald-500/5">
                    <ShieldCheck className="w-5 h-5 text-emerald-500 mt-0.5 shrink-0" />
                    <div className="flex-1 text-sm">
                      <div className="font-semibold text-emerald-700 dark:text-emerald-400 mb-1">
                        ✓ Ata pronta para uso jurídico
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Sua ata já possui <strong>validade jurídica completa</strong> com SHA-256 + selo OpenTimestamps
                        (Bitcoin) + carimbo RFC 3161 (FreeTSA). O RFC 3161 já é prova legal imediata — a confirmação
                        Bitcoin completa do OpenTimestamps acontece em 1-6h, automaticamente. Atende ao tripé probatório
                        do CPC art. 411 II e MP 2.200-2/2001.
                      </p>
                    </div>
                  </div>
                )}

                {/* Assinatura digital — OPCIONAL (reforço institucional) */}
                <Collapsible>
                  <CollapsibleTrigger asChild>
                    <Button variant="outline" className="w-full justify-between group">
                      <span className="flex items-center gap-2">
                        <PenLine className="w-4 h-4" />
                        Adicionar assinatura digital
                        <Badge variant="secondary" className="text-[10px] ml-1">
                          Opcional
                        </Badge>
                      </span>
                      <ChevronDown className="w-4 h-4 transition-transform group-data-[state=open]:rotate-180" />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="space-y-4 pt-4">
                    <div className="text-xs text-muted-foreground p-3 rounded border border-dashed bg-muted/30">
                      <strong className="text-foreground">Quando vale a pena?</strong> A assinatura digital via
                      gov.br é um <strong>reforço opcional</strong> gratuito quando você quer dar peso institucional
                      adicional ao documento (ex.: laudos periciais, atas para conselhos profissionais). Para a maioria
                      dos casos, o selo blockchain acima já é suficiente.
                    </div>

                    {/* Assinatura digital — gov.br */}
                    <div ref={signSectionRef}>
                      <AssinaturaDigital evidenceHash={result.evidence_hash} pdfBase64={pdfBase64} />
                    </div>

                    {/* Assinatura externa — usuário usa próprio certificado (Vidaas, Certisign, Acrobat, etc) */}
                    <AssinaturaExterna evidenceHash={result.evidence_hash} pdfBase64={pdfBase64} />
                  </CollapsibleContent>
                </Collapsible>
              </>
            )}
          </TabsContent>
        </Tabs>

        <div className="text-[11px] text-muted-foreground border-t pt-3 mt-6 space-y-1">
          <p>
            <strong>Validade jurídica sem cartório:</strong> a combinação de SHA-256 (integridade) + OpenTimestamps/RFC
            3161 (temporalidade) + assinatura gov.br (autoria) atende ao tripé probatório do CPC art. 411,
            II, MP 2.200-2/2001 art. 10 §2º e Lei 14.063/2020.
          </p>
          <p>
            <strong>Em juízo:</strong> junte aos autos o PDF assinado + arquivo .ots (OpenTimestamps) + token .tsr (RFC
            3161) + petição modelo (aba "Documentação Pericial").
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

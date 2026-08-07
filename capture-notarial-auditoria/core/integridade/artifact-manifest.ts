/**
 * Requisitos 4, 5, 7 e 8 — Correlação de artefatos, auditoria de payload,
 * manifesto de artefatos e Master Hash.
 */
import { canonicalStringify, sha256Hex, sha256OfBlob, sha256OfJson, utcNow } from './hash';
import type { DomChainLink } from './dom-chain';
import type { FrameChainLink, ObservationScopeInfo, SurfaceEvent } from './capture-observation';

export type ArtifactKind =
  | 'screenshot'
  | 'fullpage'
  | 'video'
  | 'dom_chain'
  | 'event_chain'
  | 'audit_report'
  | 'pdf'
  | 'other';

export interface ArtifactEntry {
  kind: ArtifactKind;
  /** Nome do arquivo dentro do pacote ZIP. */
  file_name: string;
  /** Caminho no armazenamento privado (quando aplicável). */
  storage_path?: string | null;
  sha256: string;
  size_bytes: number;
  mime?: string | null;
  captured_at: string;
  /** Requisito 4 — elo do DOM vigente no instante do artefato. */
  dom_chain_hash?: string | null;
  dom_seq?: number | null;
  /** Requisito 4 — hash do evento correspondente na cadeia da sessão. */
  event_hash?: string | null;
  event_seq?: number | null;
  notes?: string | null;
}

export interface PayloadAuditEntry {
  timestamp: string;
  endpoint: string;
  /** Hash do payload calculado ANTES do envio. */
  payload_sha256_local: string;
  /** Hash devolvido pelo servidor após persistência. */
  payload_sha256_remote: string | null;
  match: boolean;
}

export interface ArtifactManifest {
  schema: 'trace-hub/sealed-artifact-manifest';
  schema_version: '1.0';
  session_id: string;
  target_url: string;
  operator_id: string;
  operator_email?: string | null;
  started_at: string;
  ended_at: string;
  timezone_offset_minutes: number;
  user_agent: string;
  viewport: { width: number; height: number };
  event_chain: {
    count: number;
    merkle_root: string | null;
    genesis: string;
  };
  dom_chain: {
    count: number;
    final_chain_hash: string | null;
    links: DomChainLink[];
  };
  mutations_count: number;
  tamper: {
    detected: boolean;
    methods: string[];
    events_count: number;
  };
  payload_audit: PayloadAuditEntry[];
  /** Registro do áudio capturado na gravação. */
  audio?: {
    tracks: number;
    labels: string[];
    mic_mixed: boolean;
    silent: boolean;
    lost: boolean;
    peak_level: number;
    operator_accepted_no_audio: boolean;
  } | null;
  /** Escopo de observação da gravação (observada × pixel-only). */
  observation?: {
    info: ObservationScopeInfo | null;
    surface_events: SurfaceEvent[];
    /** true quando houve redimensionamento/troca da superfície durante a coleta. */
    surface_anomaly: boolean;
  } | null;
  /** Cadeia de hash de frames amostrados do vídeo. */
  video_integrity?: {
    frame_chain_count: number;
    frame_chain_final_hash: string | null;
    sample_interval_ms: number;
    links: FrameChainLink[];
  } | null;
  artifacts: ArtifactEntry[];
  /** Requisito 8 — Master Hash sobre a serialização canônica de tudo acima. */
  master_hash?: string;
  master_hash_algorithm: 'SHA-256';
  master_hash_input: 'canonical_json(manifest_without_master_hash)';
}

export async function hashArtifactBlob(blob: Blob): Promise<{ sha256: string; size_bytes: number }> {
  return { sha256: await sha256OfBlob(blob), size_bytes: blob.size };
}

/** Requisito 5 — compara o hash local do payload com o hash persistido. */
export async function auditPayload(
  endpoint: string,
  payload: unknown,
  remoteHash: string | null,
): Promise<PayloadAuditEntry> {
  const local = await sha256OfJson(payload);
  return {
    timestamp: utcNow(),
    endpoint,
    payload_sha256_local: local,
    payload_sha256_remote: remoteHash,
    match: remoteHash != null && remoteHash === local,
  };
}

/** Requisito 8 — Master Hash: hash sobre o manifesto canônico sem o próprio campo. */
export async function computeMasterHash(manifest: ArtifactManifest): Promise<string> {
  const { master_hash: _omit, ...rest } = manifest;
  return sha256Hex(canonicalStringify(rest));
}

export async function sealManifest(manifest: ArtifactManifest): Promise<ArtifactManifest> {
  const master_hash = await computeMasterHash(manifest);
  return { ...manifest, master_hash };
}

/** Revalida o Master Hash de um manifesto exportado (verificador offline). */
export async function verifyMasterHash(
  manifest: ArtifactManifest,
): Promise<{ valid: boolean; expected: string; declared: string | null }> {
  const expected = await computeMasterHash(manifest);
  return { valid: expected === (manifest.master_hash ?? null), expected, declared: manifest.master_hash ?? null };
}

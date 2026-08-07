/**
 * Requisitos 10 e 15 — Pacote ZIP forense da sessão lacrada + verificador.
 *
 * Estrutura:
 *   manifest.json                  (manifesto de artefatos + master_hash)
 *   relatorio_auditoria.json       (relatório de auditoria de integridade)
 *   cadeia_dom.json                (hash chain do DOM + mutações)
 *   cadeia_eventos.json            (eventos encadeados da sessão)
 *   cadeia_frames.json             (hash chain de quadros amostrados do vídeo)
 *   artefatos/<arquivos>           (screenshots, vídeo, PDF)
 *   HASHES.sha256.txt              (todos os SHA-256 em formato sha256sum)
 *   COMO_VERIFICAR.txt             (instruções de verificação independente)
 */
import JSZip from 'jszip';
import type { ArtifactManifest } from './artifact-manifest';
import { verifyMasterHash } from './artifact-manifest';
import type { IntegrityAuditReport } from './audit-report';
import { verifyDomChain, type DomChainLink } from './dom-chain';
import { verifyFrameChain, type FrameChainLink } from './capture-observation';
import { sha256Hex, sha256OfBlob } from './hash';

export interface SealedEventRecord {
  seq: number;
  event_type: string;
  payload_sha256: string;
  prev_hash: string;
  event_hash: string;
  created_at: string;
}

export interface SealedPackageInput {
  manifest: ArtifactManifest;
  audit: IntegrityAuditReport;
  domLinks: DomChainLink[];
  mutations: unknown[];
  events: SealedEventRecord[];
  /** Blobs dos artefatos, na mesma ordem/nome do manifesto. */
  files: Array<{ file_name: string; blob: Blob }>;
  verifyUrl: string;
}

const HOW_TO_VERIFY = (m: ArtifactManifest, verifyUrl: string) => `COMO VERIFICAR ESTE PACOTE DE FORMA INDEPENDENTE
=================================================

Sessão: ${m.session_id}
URL alvo: ${m.target_url}
Master Hash (SHA-256): ${m.master_hash ?? '(ausente)'}

1) Hash dos arquivos
   Linux/macOS:  sha256sum -c HASHES.sha256.txt
   Windows:      certutil -hashfile artefatos\\<arquivo> SHA256

2) Master Hash do manifesto
   Remova o campo "master_hash" de manifest.json, serialize o restante em JSON
   canônico (chaves ordenadas em todos os níveis, sem espaços) e calcule SHA-256.
   O resultado deve ser igual ao Master Hash acima.

3) Cadeia de eventos (cadeia_eventos.json)
   Para cada evento, em ordem de "seq":
     event_hash = SHA-256( prev_hash + "|" + payload_sha256 + "|" + created_at )
   O prev_hash do primeiro evento é ${'0'.repeat(64)}.

4) Cadeia do DOM (cadeia_dom.json)
   Para cada elo, em ordem de "seq":
     chain_hash = SHA-256( prev_hash + "|" + dom_sha256 + "|" + timestamp )
   O prev_hash do primeiro elo é ${'0'.repeat(64)}.

5) Cadeia de quadros do vídeo (cadeia_frames.json)
   Para cada elo, em ordem de "seq":
     chain_hash = SHA-256( prev_hash + "|" + frame_sha256 + "|" + timestamp )
   O prev_hash do primeiro elo é ${'0'.repeat(64)}.
   ESCOPO: quando a gravação é classificada como "pixel-only" (superfície externa
   compartilhada pelo operador), a plataforma atesta o arquivo, os horários e os
   hashes, mas não observou o DOM do conteúdo exibido (CPC, art. 411, II).

6) Verificação assistida (opcional, sem enviar arquivos)
   ${verifyUrl}
   A conferência é feita no próprio navegador: os arquivos não são transmitidos.

OBSERVAÇÃO: a ancoragem em blockchain/RFC 3161 comprova a anterioridade
temporal do hash mestre, não a veracidade do conteúdo capturado.
`;

export async function buildSealedForensicPackage(input: SealedPackageInput): Promise<Blob> {
  const zip = new JSZip();
  zip.file('manifest.json', JSON.stringify(input.manifest, null, 2));
  zip.file('relatorio_auditoria.json', JSON.stringify(input.audit, null, 2));
  zip.file(
    'cadeia_dom.json',
    JSON.stringify({ session_id: input.manifest.session_id, links: input.domLinks, mutations: input.mutations }, null, 2),
  );
  zip.file(
    'cadeia_eventos.json',
    JSON.stringify(
      { session_id: input.manifest.session_id, genesis: '0'.repeat(64), merkle_root: input.manifest.event_chain.merkle_root, events: input.events },
      null,
      2,
    ),
  );

  const frameLinks = input.manifest.video_integrity?.links ?? [];
  zip.file(
    'cadeia_frames.json',
    JSON.stringify(
      {
        session_id: input.manifest.session_id,
        genesis: '0'.repeat(64),
        sample_interval_ms: input.manifest.video_integrity?.sample_interval_ms ?? 1000,
        observation: input.manifest.observation ?? null,
        links: frameLinks,
      },
      null,
      2,
    ),
  );

  const hashLines: string[] = [];
  const artifacts = zip.folder('artefatos');
  for (const f of input.files) {
    // Mídia já é comprimida: recomprimir com DEFLATE só multiplica o pico de
    // memória da aba sem reduzir o tamanho do pacote.
    const isMedia = /\.(webm|mp4|mkv|mov|png|jpe?g|webp|gif|zip|ots|tsr)$/i.test(f.file_name);
    artifacts?.file(f.file_name, f.blob, isMedia ? { compression: 'STORE' } : undefined);
    // Reaproveita o SHA-256 já calculado no manifesto em vez de reler o arquivo.
    const declared = input.manifest.artifacts.find((a) => a.file_name === f.file_name)?.sha256;
    hashLines.push(`${declared ?? (await sha256OfBlob(f.blob))}  artefatos/${f.file_name}`);
  }
  for (const [name, content] of [
    ['manifest.json', JSON.stringify(input.manifest, null, 2)],
    ['relatorio_auditoria.json', JSON.stringify(input.audit, null, 2)],
  ] as const) {
    hashLines.push(`${await sha256Hex(content)}  ${name}`);
  }
  zip.file('HASHES.sha256.txt', hashLines.join('\n') + '\n');
  zip.file('COMO_VERIFICAR.txt', HOW_TO_VERIFY(input.manifest, input.verifyUrl));

  return zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 } });

}

export interface SealedPackageVerification {
  ok: boolean;
  master_hash: { valid: boolean; expected: string; declared: string | null };
  dom_chain: { valid: boolean; brokenAt: number | null; count: number };
  event_chain: { valid: boolean; brokenAt: number | null; count: number };
  frame_chain: { valid: boolean; brokenAt: number | null; count: number };
  observation: { scope: string; surface_anomaly: boolean } | null;
  files: Array<{ file_name: string; declared: string; computed: string | null; valid: boolean }>;
  errors: string[];
}

async function verifyEventChain(events: SealedEventRecord[]) {
  let prev = '0'.repeat(64);
  const sorted = [...events].sort((a, b) => a.seq - b.seq);
  for (const e of sorted) {
    if (e.prev_hash !== prev) return { valid: false, brokenAt: e.seq, count: sorted.length };
    const expected = await sha256Hex(`${e.prev_hash}|${e.payload_sha256}|${e.created_at}`);
    if (expected !== e.event_hash) return { valid: false, brokenAt: e.seq, count: sorted.length };
    prev = e.event_hash;
  }
  return { valid: true, brokenAt: null, count: sorted.length };
}

/** Requisito 10 — verificador offline: valida um ZIP inteiro no navegador. */
export async function verifySealedForensicPackage(zipFile: Blob): Promise<SealedPackageVerification> {
  const errors: string[] = [];
  const zip = await JSZip.loadAsync(zipFile);

  const readJson = async <T,>(name: string): Promise<T | null> => {
    const entry = zip.file(name);
    if (!entry) {
      errors.push(`Arquivo ausente no pacote: ${name}`);
      return null;
    }
    try {
      return JSON.parse(await entry.async('string')) as T;
    } catch {
      errors.push(`JSON inválido: ${name}`);
      return null;
    }
  };

  const manifest = await readJson<ArtifactManifest>('manifest.json');
  const domChain = await readJson<{ links: DomChainLink[] }>('cadeia_dom.json');
  const eventChain = await readJson<{ events: SealedEventRecord[] }>('cadeia_eventos.json');
  const frameChainFile = zip.file('cadeia_frames.json')
    ? await readJson<{ links: FrameChainLink[] }>('cadeia_frames.json')
    : null;

  const master = manifest
    ? await verifyMasterHash(manifest)
    : { valid: false, expected: '', declared: null as string | null };
  const dom = domChain?.links ? await verifyDomChain(domChain.links) : { valid: true, brokenAt: null, count: 0 };
  const evc = eventChain?.events ? await verifyEventChain(eventChain.events) : { valid: true, brokenAt: null, count: 0 };

  const frames = frameChainFile?.links
    ? await verifyFrameChain(frameChainFile.links)
    : { valid: true, brokenAt: null, count: 0 };

  const files: SealedPackageVerification['files'] = [];
  for (const a of manifest?.artifacts ?? []) {
    const entry = zip.file(`artefatos/${a.file_name}`);
    if (!entry) {
      // Mídia muito grande é distribuída fora do ZIP (com hash declarado no
      // manifesto): não é ausência de artefato, é distribuição separada.
      const distributedApart = a.kind === 'video' && !!a.storage_path;
      files.push({ file_name: a.file_name, declared: a.sha256, computed: null, valid: distributedApart });
      if (!distributedApart) {
        errors.push(`Artefato declarado no manifesto não está no pacote: ${a.file_name}`);
      }

      continue;
    }
    const computed = await sha256OfBlob(await entry.async('blob'));
    files.push({ file_name: a.file_name, declared: a.sha256, computed, valid: computed === a.sha256 });
  }


  const ok =
    errors.length === 0 &&
    master.valid &&
    dom.valid &&
    evc.valid &&
    frames.valid &&
    files.every((f) => f.valid);
  return {
    ok,
    master_hash: master,
    dom_chain: dom,
    event_chain: evc,
    frame_chain: frames,
    observation: manifest?.observation
      ? {
          scope: manifest.observation.info?.scope ?? 'pixel_only',
          surface_anomaly: !!manifest.observation.surface_anomaly,
        }
      : null,
    files,
    errors,
  };
}

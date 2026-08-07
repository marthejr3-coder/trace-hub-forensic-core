/**
 * platform-provenance.ts
 * ======================
 * Procedência da plataforma que produziu a evidência: build do bundle,
 * ambiente de execução e SHA-256 do binário desktop publicado.
 *
 * Regras rígidas:
 *  • Nada é inventado. Só expomos o que a plataforma realmente conhece.
 *  • NÃO chamamos de "assinatura digital": o que temos é o SHA-256 do binário
 *    publicado. Verificação de cadeia Authenticode/Apple é feita pelo SO.
 *  • Falha de rede nunca bloqueia a geração de relatório — cai no fallback
 *    com build tag + runtime.
 *  • A plataforma é exclusivamente web; não há binário desktop distribuído.
 */
import { BUILD_TAG } from '@/lib/build-info';
import { supabase } from '@/integrations/supabase/client';

/** Página pública que lista os hashes e artefatos auditáveis da plataforma. */
export const PUBLIC_VERIFICATION_URL = 'https://www.trace-hub.com/auditoria-publica';

export interface DesktopReleaseHash {
  platform: string;
  version: string;
  sha256: string;
}

export interface PlatformProvenance {
  /** Tag do build do bundle web em execução. */
  buildTag: string;
  runtime: 'web' | 'desktop';
  /** Preenchido quando runtime === 'desktop'. */
  desktop?: {
    appVersion: string;
    platform: string;
    arch: string;
    binarySha256: string;
    binaryPath?: string;
  };
  /** Hashes dos binários desktop marcados como versão corrente. */
  publishedReleases: DesktopReleaseHash[];
  publicVerificationUrl: string;
}

const PLATFORM_LABEL: Record<string, string> = {
  win32: 'Windows',
  windows: 'Windows',
  darwin: 'macOS',
  macos: 'macOS',
  mac: 'macOS',
  linux: 'Linux',
  android: 'Android',
};

export function platformLabel(p?: string | null): string {
  if (!p) return '—';
  return PLATFORM_LABEL[p.toLowerCase()] || p;
}

export function runtimeLabel(prov: PlatformProvenance): string {
  if (prov.runtime === 'desktop' && prov.desktop) {
    return `Trace Hub Desktop ${prov.desktop.appVersion} (${platformLabel(prov.desktop.platform)} ${prov.desktop.arch})`;
  }
  return 'Navegador (aplicação web Trace Hub)';
}

function fallback(): PlatformProvenance {
  return {
    buildTag: BUILD_TAG,
    runtime: 'web',
    publishedReleases: [],
    publicVerificationUrl: PUBLIC_VERIFICATION_URL,
  };
}

let cache: PlatformProvenance | null = null;
let inflight: Promise<PlatformProvenance> | null = null;

/**
 * Carrega (e memoiza) a procedência da plataforma. Deve ser chamada pelos
 * callers antes de gerar o PDF; geradores sincronos usam
 * `getPlatformProvenanceSync()`.
 */
export async function loadPlatformProvenance(): Promise<PlatformProvenance> {
  if (cache) return cache;
  if (inflight) return inflight;

  inflight = (async (): Promise<PlatformProvenance> => {
    const result = fallback();
    cache = result;
    return result;
  })();

  try {
    return await inflight;
  } finally {
    inflight = null;
  }
}

/** Snapshot já carregado (ou fallback determinístico). Nunca lança. */
export function getPlatformProvenanceSync(): PlatformProvenance {
  return cache ?? fallback();
}

export const PLATFORM_PROVENANCE_TITLE = 'Procedência da Plataforma';

export const PLATFORM_PROVENANCE_NOTE =
  'Os valores acima identificam a versão exata da plataforma web que produziu esta evidência. ' +
  'A tag de build permite conferir, na página pública de verificação, qual versão do sistema ' +
  'estava em execução no momento da coleta.';

/** Linhas rótulo/valor do bloco, prontas para PDF ou texto. */
export function buildPlatformProvenanceRows(prov: PlatformProvenance): [string, string][] {
  const rows: [string, string][] = [
    ['Build do bundle', prov.buildTag || '—'],
    ['Ambiente de execução', runtimeLabel(prov)],
  ];

  if (prov.desktop) {
    rows.push(['SHA-256 do executável em uso', prov.desktop.binarySha256 || '—']);
  }

  prov.publishedReleases.forEach((r) => {
    rows.push([
      `SHA-256 binário publicado (${platformLabel(r.platform)}${r.version ? ' ' + r.version : ''})`,
      r.sha256,
    ]);
  });

  rows.push(['Verificação pública', prov.publicVerificationUrl]);
  return rows;
}

/** Versão texto puro do bloco, para READMEs e METODOLOGIA_TECNICA.txt dos ZIPs. */
export function buildPlatformProvenanceTextBlock(prov: PlatformProvenance): string {
  const rows = buildPlatformProvenanceRows(prov);
  const width = Math.max(...rows.map(([l]) => l.length));
  const body = rows.map(([l, v]) => `${l.padEnd(width)} : ${v}`).join('\n');
  return [
    PLATFORM_PROVENANCE_TITLE.toUpperCase(),
    '='.repeat(PLATFORM_PROVENANCE_TITLE.length),
    '',
    body,
    '',
    PLATFORM_PROVENANCE_NOTE,
  ].join('\n');
}

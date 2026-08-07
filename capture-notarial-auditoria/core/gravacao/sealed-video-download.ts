import { supabase } from '@/integrations/supabase/client';

export interface SealedVideoRef {
  video_path?: string | null;
  video_bucket?: string | null;
  video_signed_url?: string | null;
  video_signed_url_expires_at?: string | null;
  video_mime?: string | null;
  video_size?: number | null;
  session_id?: string | null;
  ended_at?: string | null;
}

const DEFAULT_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 dias

function extFromMime(mime?: string | null, fallbackPath?: string | null): string {
  if (mime) {
    const m = mime.toLowerCase();
    if (m.includes('webm')) return 'webm';
    if (m.includes('mp4')) return 'mp4';
    if (m.includes('matroska') || m.includes('mkv')) return 'mkv';
    if (m.includes('quicktime') || m.includes('mov')) return 'mov';
  }
  if (fallbackPath) {
    const m = fallbackPath.match(/\.([a-z0-9]+)(?:\?.*)?$/i);
    if (m) return m[1].toLowerCase();
  }
  return 'webm';
}

export function buildFriendlyFilename(ref: SealedVideoRef): string {
  const date = ref.ended_at ? new Date(ref.ended_at) : new Date();
  const pad = (n: number) => n.toString().padStart(2, '0');
  const stamp = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}`;
  const ext = extFromMime(ref.video_mime, ref.video_path);
  return `captura-lacrada-${stamp}.${ext}`;
}

function isSignedUrlValid(ref: SealedVideoRef): boolean {
  if (!ref.video_signed_url) return false;
  if (!ref.video_signed_url_expires_at) return true; // assume válida
  const exp = new Date(ref.video_signed_url_expires_at).getTime();
  // 5 min de folga
  return Number.isFinite(exp) && exp - Date.now() > 5 * 60 * 1000;
}

async function regenerateSignedUrl(ref: SealedVideoRef): Promise<string | null> {
  if (!ref.video_path) return null;
  const bucket = ref.video_bucket || 'sealed-capture';
  const { data, error } = await supabase.storage
    .from(bucket)
    .createSignedUrl(ref.video_path, DEFAULT_TTL_SECONDS);
  if (error || !data?.signedUrl) return null;
  return data.signedUrl;
}

/**
 * Força download real do vídeo (sem abrir no navegador como aba).
 * - Usa link assinado se válido; senão regenera via storage.
 * - Faz fetch + Blob para garantir o filename amigável em qualquer navegador.
 */
export async function downloadSealedVideo(ref: SealedVideoRef): Promise<void> {
  let url = isSignedUrlValid(ref) ? ref.video_signed_url! : await regenerateSignedUrl(ref);
  if (!url) {
    throw new Error('Não foi possível obter a URL do vídeo. Tente recarregar a página.');
  }
  const filename = buildFriendlyFilename(ref);

  // Caminho preferido: fetch + Blob (mantém filename e força download)
  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const blob = await resp.blob();
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Revoga depois para evitar cancelar download em navegadores lentos
    setTimeout(() => URL.revokeObjectURL(objectUrl), 3000);
    return;
  } catch {
    // Fallback: anchor direto (pode abrir aba dependendo do navegador)
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
}

export function formatMB(bytes?: number | null): string | null {
  if (bytes == null) return null;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

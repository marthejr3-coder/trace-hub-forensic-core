/**
 * Selo temporal independente — wrapper único para todas as ferramentas
 * forenses de coleta primária. Atende CPP art. 158-D + STJ HC 1.069.334
 * (impossibilidade de pré-datação da evidência).
 *
 * Usa OriginStamp v4 multi-chain (BTC/ETH/IPFS) + RFC 3161 FreeTSA via a
 * Edge Function `originstamp-anchor` (mesma usada pela Ata Notarial).
 */
import { supabase } from '@/integrations/supabase/client';

export interface ForensicTimestamp {
  hash: string;
  attested_at: string;
  anchor_url?: string | null;
  ots_base64?: string | null;
  tsr_base64?: string | null;
  status: 'sealed' | 'pending' | 'failed';
  error?: string;
}

export async function sealForensicHash(
  hash: string,
  context: { tool: string; session_id?: string } = { tool: 'unknown' },
): Promise<ForensicTimestamp> {
  try {
    const { data, error } = await supabase.functions.invoke('originstamp-anchor', {
      body: { hash, context },
    });
    if (error) throw error;
    return {
      hash,
      attested_at: data?.attested_at ?? new Date().toISOString(),
      anchor_url: data?.anchor_url ?? null,
      ots_base64: data?.ots_base64 ?? null,
      tsr_base64: data?.tsr_base64 ?? null,
      status: 'sealed',
    };
  } catch (e: any) {
    console.warn('[forensic-timestamp] selo indisponível:', e?.message);
    return {
      hash,
      attested_at: new Date().toISOString(),
      status: 'pending',
      error: e?.message ?? String(e),
    };
  }
}

/** Formato curto para impressão em PDFs. */
export function formatTimestampLine(ts: ForensicTimestamp): string {
  if (ts.status === 'sealed') {
    return `Selado em ${new Date(ts.attested_at).toLocaleString('pt-BR')} · OriginStamp multi-chain + RFC 3161`;
  }
  if (ts.status === 'pending') {
    return `Selo temporal pendente (hash registrado em ${new Date(ts.attested_at).toLocaleString('pt-BR')})`;
  }
  return `Falha ao selar: ${ts.error ?? 'erro desconhecido'}`;
}

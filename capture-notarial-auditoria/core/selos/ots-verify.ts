/**
 * Verificação de OpenTimestamps (.ots) — roteada pela Edge Function
 * `originstamp-verify`, que usa a biblioteca oficial `opentimestamps` no
 * servidor para fazer o "upgrade" da prova e contorna CORS do navegador.
 */
import { supabase } from '@/integrations/supabase/client';

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function findBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

export interface OtsVerifyResult {
  ok: boolean;
  fileSha256: string;
  digestPresent: boolean;
  calendarStatus: 'confirmed' | 'pending' | 'unknown';
  bitcoinHeight: number | null;
  merkleRoot: string | null;
  calendarMessage: string;
  notes: string[];
}

export async function verifyOts(otsFile: File, originalFile: File): Promise<OtsVerifyResult> {
  const notes: string[] = [];
  const otsBuf = new Uint8Array(await otsFile.arrayBuffer());
  const fileBuf = await originalFile.arrayBuffer();
  const sha256Buf = new Uint8Array(await crypto.subtle.digest('SHA-256', fileBuf));
  const fileSha256 = toHex(sha256Buf);
  const digestPresent = findBytes(otsBuf, sha256Buf) !== -1;
  if (!digestPresent) {
    notes.push(
      'O SHA-256 do arquivo enviado não foi localizado no .ots. Confirme que o arquivo original é exatamente o que foi selado pelo Trace Hub (sem reabrir/salvar).',
    );
  }

  let calendarStatus: OtsVerifyResult['calendarStatus'] = 'unknown';
  let bitcoinHeight: number | null = null;
  let calendarMessage = '';

  try {
    const { data, error } = await supabase.functions.invoke('originstamp-verify', {
      body: {
        evidence_hash: fileSha256,
        ots_base64: bytesToBase64(otsBuf),
      },
    });
    if (error) throw error;

    if (data?.confirmed) {
      calendarStatus = 'confirmed';
      bitcoinHeight = data.block_height ?? null;
      calendarMessage = data.notice || 'Confirmação Bitcoin via OpenTimestamps detectada.';
    } else if (data?.success) {
      calendarStatus = 'pending';
      calendarMessage =
        data.notice ||
        'Calendar consultado: ainda sem bloco Bitcoin confirmado. Aguarde de 1 a 6 horas após a selagem.';
    } else {
      calendarMessage = data?.error || 'Resposta inesperada da verificação.';
    }

    if (Array.isArray(data?.checks) && data.checks.length) {
      const breakdown = data.checks
        .map((c: any) => `${c.calendar}: ${c.confirmed ? 'OK' : c.note || 'não agregado'}`)
        .join(' · ');
      notes.push(breakdown);
    }
  } catch (e: any) {
    calendarMessage = `Falha ao consultar verificador: ${e?.message || e}`;
  }

  notes.push(
    'Após selagem, a confirmação Bitcoin via OpenTimestamps pode levar de 1 a 6 horas. Enquanto isso, a prova RFC 3161 (.tsr) já tem validade jurídica plena.',
  );

  return {
    ok: digestPresent && calendarStatus === 'confirmed',
    fileSha256,
    digestPresent,
    calendarStatus,
    bitcoinHeight,
    merkleRoot: null,
    calendarMessage,
    notes,
  };
}

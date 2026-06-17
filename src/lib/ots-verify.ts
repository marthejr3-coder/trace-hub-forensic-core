/**
 * Verificação leve de OpenTimestamps:
 * - Calcula SHA-256 do arquivo
 * - Confirma que o digest está presente no .ots
 * - Consulta o calendar Alice para status de confirmação
 */

const CALENDAR = 'https://alice.btc.calendar.opentimestamps.org';

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
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

/**
 * Tag de attestation Bitcoin no protocolo OpenTimestamps.
 * Detecção determinística — corrige F-04 do laudo (substitui heurística de tamanho/string).
 */
const BITCOIN_ATTESTATION_TAG = new Uint8Array([
  0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
]);

function detectBitcoinAttestation(buf: Uint8Array): { confirmed: boolean; blockHeight: number | null } {
  const idx = findBytes(buf, BITCOIN_ATTESTATION_TAG);
  if (idx < 0) return { confirmed: false, blockHeight: null };
  let off = idx + BITCOIN_ATTESTATION_TAG.length;
  while (off < buf.length && (buf[off] & 0x80)) off++;
  off++;
  let h = 0;
  let shift = 0;
  while (off < buf.length) {
    const b = buf[off++];
    h |= (b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7;
    if (shift > 28) return { confirmed: true, blockHeight: null };
  }
  return { confirmed: true, blockHeight: h > 0 ? h : null };
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
  if (!digestPresent) notes.push('Hash SHA-256 do arquivo NÃO foi localizado no payload do .ots.');

  let calendarStatus: OtsVerifyResult['calendarStatus'] = 'unknown';
  let bitcoinHeight: number | null = null;
  let merkleRoot: string | null = null;
  let calendarMessage = '';

  try {
    const url = `${CALENDAR}/timestamp/${fileSha256}`;
    const r = await fetch(url, { method: 'GET' });
    if (r.status === 200) {
      const data = new Uint8Array(await r.arrayBuffer());
      const att = detectBitcoinAttestation(data);
      if (att.confirmed) {
        calendarStatus = 'confirmed';
        bitcoinHeight = att.blockHeight;
        calendarMessage = att.blockHeight
          ? `Attestation Bitcoin detectada (bloco #${att.blockHeight}).`
          : 'Attestation Bitcoin detectada no payload do calendar.';
      } else {
        calendarStatus = 'pending';
        calendarMessage = `Calendar respondeu (${data.length} bytes), mas sem tag de attestation Bitcoin ainda — confirmação Bitcoin pendente.`;
      }
    } else if (r.status === 404) {
      calendarStatus = 'pending';
      calendarMessage = 'Calendar Alice ainda não conhece esse digest (pendente). Tente novamente em algumas horas.';
    } else {
      await r.text().catch(() => {});
      calendarMessage = `Calendar respondeu HTTP ${r.status}.`;
    }
  } catch (e: any) {
    calendarMessage = `Falha de rede ao consultar Calendar (CORS/offline): ${e?.message || e}`;
  }

  notes.push('Confirmação completa requer agregação de múltiplos calendars e parsing da árvore Merkle até a transação Bitcoin. Esta verificação é resumida.');

  return {
    ok: digestPresent && calendarStatus === 'confirmed',
    fileSha256,
    digestPresent,
    calendarStatus,
    bitcoinHeight,
    merkleRoot,
    calendarMessage,
    notes,
  };
}

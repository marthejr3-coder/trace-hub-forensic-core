/**
 * Verificação de timestamps RFC 3161 (.tsr) — extrai messageImprint e
 * compara com o hash do arquivo original.
 *
 * Parser DER estrutural (recursivo), sem heurística de varredura linear.
 * Corrige F-01 do laudo de auditoria forense (Jun/2026):
 *   - Desce a árvore ContentInfo → SignedData → encapContentInfo → TSTInfo.
 *   - Valida AlgorithmIdentifier (OID) ANTES da OCTET STRING do messageImprint.
 *   - Extrai genTime apenas de dentro do TSTInfo (não a primeira GeneralizedTime qualquer).
 *   - Extrai serialNumber do TSTInfo (campo que antes era sempre null).
 *
 * Não valida cadeia X.509/CMS completa (declarado no laudo, fora do escopo client-side).
 */

const FREETSA_CERT_URL = 'https://freetsa.org/files/tsa.crt';

// ---- OIDs relevantes (RFC 3161 / PKIX) ---------------------------------
const OID_ID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_SHA1 = '1.3.14.3.2.26';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
const OID_SHA512 = '2.16.840.1.101.3.4.2.3';

const HASH_OID_TO_NAME: Record<string, string> = {
  [OID_SHA1]: 'SHA-1',
  [OID_SHA256]: 'SHA-256',
  [OID_SHA384]: 'SHA-384',
  [OID_SHA512]: 'SHA-512',
};

// ---- Parser DER mínimo --------------------------------------------------
interface DerNode {
  tag: number;
  constructed: boolean;
  start: number;
  contentStart: number;
  contentEnd: number; // exclusivo
}

function readDer(buf: Uint8Array, offset: number): DerNode {
  if (offset >= buf.length) throw new Error('DER: offset fora dos limites');
  const tag = buf[offset];
  const constructed = (tag & 0x20) !== 0;
  let lenByte = buf[offset + 1];
  let length: number;
  let contentStart: number;
  if (lenByte === 0x80) {
    throw new Error('DER: indefinite length não permitido em DER');
  }
  if (lenByte < 0x80) {
    length = lenByte;
    contentStart = offset + 2;
  } else {
    const lenBytes = lenByte & 0x7f;
    if (lenBytes > 4) throw new Error('DER: length > 4 bytes não suportado');
    length = 0;
    for (let i = 0; i < lenBytes; i++) length = (length << 8) | buf[offset + 2 + i];
    contentStart = offset + 2 + lenBytes;
  }
  const contentEnd = contentStart + length;
  if (contentEnd > buf.length) throw new Error('DER: comprimento excede buffer');
  return { tag, constructed, start: offset, contentStart, contentEnd };
}

function children(buf: Uint8Array, parent: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let off = parent.contentStart;
  while (off < parent.contentEnd) {
    const node = readDer(buf, off);
    out.push(node);
    off = node.contentEnd;
  }
  return out;
}

function decodeOid(buf: Uint8Array, node: DerNode): string {
  if (node.tag !== 0x06) throw new Error('Esperava OID');
  const data = buf.slice(node.contentStart, node.contentEnd);
  if (data.length === 0) return '';
  const first = data[0];
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let v = 0;
  for (let i = 1; i < data.length; i++) {
    v = (v << 7) | (data[i] & 0x7f);
    if ((data[i] & 0x80) === 0) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

function decodeInteger(buf: Uint8Array, node: DerNode): string {
  if (node.tag !== 0x02) throw new Error('Esperava INTEGER');
  return Array.from(buf.slice(node.contentStart, node.contentEnd))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function decodeGenTime(buf: Uint8Array, node: DerNode): string {
  if (node.tag !== 0x18) throw new Error('Esperava GeneralizedTime');
  return new TextDecoder().decode(buf.slice(node.contentStart, node.contentEnd));
}

// ---- Localização do TSTInfo dentro do TSR -------------------------------
/**
 * Estrutura RFC 3161:
 *   TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
 *   ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
 *   SignedData ::= SEQUENCE { version, digestAlgs, encapContentInfo, ... }
 *   encapContentInfo ::= SEQUENCE { eContentType OID (=id-ct-TSTInfo), eContent [0] EXPLICIT OCTET STRING containing TSTInfo }
 *   TSTInfo ::= SEQUENCE { version INTEGER, policy OID, messageImprint MessageImprint, serialNumber INTEGER, genTime GeneralizedTime, ... }
 *   MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
 */
function findTstInfo(buf: Uint8Array): DerNode | null {
  // Caminha pela árvore tolerando que o TSR pode ou não ter o wrapper PKIStatusInfo.
  let root: DerNode;
  try {
    root = readDer(buf, 0);
  } catch {
    return null;
  }
  if (root.tag !== 0x30) return null;

  // Procura recursivamente um SEQUENCE cujo primeiro filho seja o OID id-ct-TSTInfo
  // (encapContentInfo). O conteúdo do segundo filho [0] EXPLICIT contém uma OCTET STRING
  // cujos bytes são o TSTInfo SEQUENCE codificado em DER.
  const stack: DerNode[] = [root];
  while (stack.length > 0) {
    const node = stack.pop()!;
    if (!node.constructed) continue;
    let kids: DerNode[];
    try {
      kids = children(buf, node);
    } catch {
      continue;
    }
    // Detecta encapContentInfo: SEQUENCE { OID id-ct-TSTInfo, [0] EXPLICIT OCTET STRING }
    if (
      node.tag === 0x30 &&
      kids.length >= 2 &&
      kids[0].tag === 0x06
    ) {
      try {
        const oid = decodeOid(buf, kids[0]);
        if (oid === OID_ID_CT_TSTINFO) {
          // Segundo filho é [0] EXPLICIT (tag 0xA0) contendo OCTET STRING (0x04)
          const explicit = kids[1];
          const inner = children(buf, explicit);
          if (inner.length >= 1 && inner[0].tag === 0x04) {
            // Os bytes da OCTET STRING são o TSTInfo SEQUENCE
            const tstInfoBytes = buf.slice(inner[0].contentStart, inner[0].contentEnd);
            const tstNode = readDer(tstInfoBytes, 0);
            // Devolvemos um nó "rebaseado" — note que os offsets são relativos a tstInfoBytes
            (tstNode as any).__buf = tstInfoBytes;
            return tstNode;
          }
        }
      } catch {
        /* segue varrendo */
      }
    }
    // Empilha filhos para continuar a busca
    for (const k of kids) stack.push(k);
  }
  return null;
}

interface TstFields {
  imprintAlgoOid: string;
  imprintAlgoName: string;
  imprintHash: Uint8Array;
  serialHex: string | null;
  genTime: string | null;
}

function parseTstInfo(tstNode: DerNode): TstFields {
  const buf: Uint8Array = (tstNode as any).__buf;
  if (tstNode.tag !== 0x30) throw new Error('TSTInfo não é SEQUENCE');
  const kids = children(buf, tstNode);
  // version(0) INTEGER, policy(1) OID, messageImprint(2) SEQUENCE, serialNumber(3) INTEGER, genTime(4) GeneralizedTime
  if (kids.length < 5) throw new Error('TSTInfo com menos campos que o esperado');
  const messageImprint = kids[2];
  if (messageImprint.tag !== 0x30) throw new Error('messageImprint não é SEQUENCE');
  const miKids = children(buf, messageImprint);
  if (miKids.length < 2) throw new Error('MessageImprint malformado');
  const algIdSeq = miKids[0];
  if (algIdSeq.tag !== 0x30) throw new Error('AlgorithmIdentifier não é SEQUENCE');
  const algKids = children(buf, algIdSeq);
  if (algKids.length < 1 || algKids[0].tag !== 0x06) throw new Error('AlgorithmIdentifier sem OID');
  const oid = decodeOid(buf, algKids[0]);
  const hashOctet = miKids[1];
  if (hashOctet.tag !== 0x04) throw new Error('hashedMessage não é OCTET STRING');
  const imprintHash = buf.slice(hashOctet.contentStart, hashOctet.contentEnd);

  const serial = kids[3];
  const serialHex = serial.tag === 0x02 ? decodeInteger(buf, serial) : null;

  const gt = kids[4];
  const genTime = gt.tag === 0x18 ? decodeGenTime(buf, gt) : null;

  return {
    imprintAlgoOid: oid,
    imprintAlgoName: HASH_OID_TO_NAME[oid] ?? `OID ${oid}`,
    imprintHash,
    serialHex,
    genTime,
  };
}

// ---- Helpers ------------------------------------------------------------
function toHex(buf: Uint8Array): string {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fmtGenTime(g: string): string {
  // YYYYMMDDhhmmss[.fff]Z → ISO
  const y = g.slice(0, 4),
    mo = g.slice(4, 6),
    d = g.slice(6, 8);
  const h = g.slice(8, 10),
    mi = g.slice(10, 12),
    s = g.slice(12, 14);
  return `${y}-${mo}-${d}T${h}:${mi}:${s}Z`;
}

export interface TsrVerifyResult {
  ok: boolean;
  fileHashSha256: string;
  fileHashSha512: string;
  imprintHashHex: string | null;
  imprintAlgo: string;
  hashMatch: boolean;
  timestampUtc: string | null;
  issuer: string | null;
  serial: string | null;
  certFetched: boolean;
  certFingerprintSha256: string | null;
  notes: string[];
}

export async function verifyTsr(tsrFile: File, originalFile: File): Promise<TsrVerifyResult> {
  const notes: string[] = [];
  const tsrBuf = new Uint8Array(await tsrFile.arrayBuffer());
  const fileBuf = await originalFile.arrayBuffer();

  const [sha256Buf, sha512Buf] = await Promise.all([
    crypto.subtle.digest('SHA-256', fileBuf),
    crypto.subtle.digest('SHA-512', fileBuf),
  ]);
  const fileHashSha256 = toHex(new Uint8Array(sha256Buf));
  const fileHashSha512 = toHex(new Uint8Array(sha512Buf));

  let imprintHashHex: string | null = null;
  let imprintAlgo = 'desconhecido';
  let genTimeStr: string | null = null;
  let serialHex: string | null = null;

  try {
    const tstNode = findTstInfo(tsrBuf);
    if (!tstNode) {
      notes.push('Estrutura TSTInfo não localizada no TSR (DER inválido ou não é RFC 3161).');
    } else {
      const parsed = parseTstInfo(tstNode);
      imprintAlgo = parsed.imprintAlgoName;
      imprintHashHex = toHex(parsed.imprintHash);
      genTimeStr = parsed.genTime;
      serialHex = parsed.serialHex;
    }
  } catch (e) {
    notes.push(`Falha no parse DER do TSR: ${e instanceof Error ? e.message : String(e)}`);
  }

  let hashMatch = false;
  if (imprintHashHex) {
    if (imprintAlgo === 'SHA-256') hashMatch = imprintHashHex === fileHashSha256;
    else if (imprintAlgo === 'SHA-512') hashMatch = imprintHashHex === fileHashSha512;
    else notes.push(`Hash do TSR é ${imprintAlgo}; comparação automática só com SHA-256/512.`);
  }

  let certFetched = false;
  let certFingerprint: string | null = null;
  try {
    const r = await fetch(FREETSA_CERT_URL);
    if (r.ok) {
      const cert = new Uint8Array(await r.arrayBuffer());
      const fp = await crypto.subtle.digest('SHA-256', cert);
      certFingerprint = toHex(new Uint8Array(fp));
      certFetched = true;
    }
  } catch {
    notes.push('Não foi possível baixar tsa.crt do FreeTSA (offline?).');
  }

  notes.push(
    'Verificação criptográfica do messageImprint contra o hash do arquivo via parser DER estrutural (RFC 3161). Validação completa da cadeia X.509/CMS não é realizada client-side.',
  );

  return {
    ok: hashMatch,
    fileHashSha256,
    fileHashSha512,
    imprintHashHex,
    imprintAlgo,
    hashMatch,
    timestampUtc: genTimeStr ? fmtGenTime(genTimeStr) : null,
    issuer: 'FreeTSA (verificar via tsa.crt fingerprint abaixo)',
    serial: serialHex,
    certFetched,
    certFingerprintSha256: certFingerprint,
    notes,
  };
}

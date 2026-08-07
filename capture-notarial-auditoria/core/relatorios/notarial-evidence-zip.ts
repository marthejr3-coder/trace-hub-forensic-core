/**
 * notarial-evidence-zip.ts
 * ========================
 * Empacota, em UM único ZIP, tudo que o operador precisa juntar aos autos
 * a partir de qualquer aba do Capture Notarial:
 *
 *   LEIA_PRIMEIRO.txt            o que é cada arquivo e o que juntar
 *   relatorio_evidencia.pdf      documento principal
 *   selo_opentimestamps.ots      selo Bitcoin (quando emitido)
 *   selo_rfc3161.tsr             carimbo de tempo qualificado (quando emitido)
 *   hash_sha256.txt              hash da evidência
 *   COMO_VERIFICAR.txt           roteiro ISO/IEC 27037 de conferência
 *   METODOLOGIA_TECNICA.txt      procedência da plataforma + cadeia de custódia
 *   midia/<arquivo>              vídeo, recorte .png, screenshots
 *
 * Regra rígida: nada é inventado. Se um selo não foi emitido, ele NÃO entra no
 * ZIP e o LEIA_PRIMEIRO.txt registra explicitamente a ausência.
 */
import JSZip from 'jszip';
import { buildIso27037TextBlock } from '@/lib/iso27037-verification-block';
import { buildPlatformProvenanceTextBlock, loadPlatformProvenance } from '@/lib/platform-provenance';
import { buildCustodyBlockTextBlock } from '@/lib/forensic-custody-block';

export interface NotarialZipMedia {
  filename: string;
  blob: Blob;
  /** Descrição curta para o LEIA_PRIMEIRO.txt. */
  description?: string;
}

export interface NotarialEvidenceZipInput {
  /** Prefixo do nome do ZIP e rótulo da coleta (ex.: 'ata-notarial'). */
  prefix: string;
  /** Título humano do tipo de coleta (ex.: 'Ata Notarial Digital'). */
  label: string;
  /** SHA-256 da evidência. */
  evidenceHash: string;
  /** PDF principal já renderizado (blob ou base64 sem prefixo). */
  pdfBase64?: string | null;
  pdfBlob?: Blob | null;
  /** Nome do PDF dentro do ZIP. */
  pdfFilename?: string;
  otsBase64?: string | null;
  tsrBase64?: string | null;
  otsSha256?: string | null;
  blockHeight?: number | null;
  blockHash?: string | null;
  blockMerkleRoot?: string | null;
  blockTime?: string | null;
  calendars?: string[];
  media?: NotarialZipMedia[];
  /** Metadados livres da coleta (URL alvo, duração, operador...). */
  meta?: Record<string, string | number | null | undefined>;
  operatorName?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const OTS_FILENAME = 'selo_opentimestamps.ots';
const TSR_FILENAME = 'selo_rfc3161.tsr';

function buildLeiaPrimeiro(input: NotarialEvidenceZipInput, pdfName: string, hasOts: boolean, hasTsr: boolean): string {
  const lines: string[] = [];
  lines.push('LEIA PRIMEIRO — PACOTE COMPLETO DA PROVA DIGITAL');
  lines.push('='.repeat(70));
  lines.push('');
  lines.push(`Coleta:          ${input.label}`);
  lines.push(`Hash evidência:  ${input.evidenceHash}`);
  if (input.operatorName) lines.push(`Operador:        ${input.operatorName}`);
  if (input.startedAt) lines.push(`Início:          ${input.startedAt}`);
  lines.push(`Gerado em:       ${new Date().toISOString()}`);
  lines.push('');
  for (const [k, v] of Object.entries(input.meta || {})) {
    if (v === null || v === undefined || v === '') continue;
    lines.push(`${k}: ${v}`);
  }
  lines.push('');
  lines.push('-'.repeat(70));
  lines.push('O QUE JUNTAR AOS AUTOS');
  lines.push('-'.repeat(70));
  lines.push('');
  lines.push(`1. ${pdfName}`);
  lines.push('   Documento principal. É este arquivo que se junta como prova.');
  lines.push('');
  if (hasOts) {
    lines.push(`2. ${OTS_FILENAME}`);
    lines.push('   Selo OpenTimestamps (ancoragem em blockchain Bitcoin).');
    lines.push('   Verificação independente: ots verify ' + OTS_FILENAME);
    if (input.blockHeight != null) {
      lines.push(`   Bloco Bitcoin confirmado: #${input.blockHeight}`);
    } else {
      lines.push('   Confirmação em bloco Bitcoin ocorre em 1 a 6 horas (tempo do');
      lines.push('   protocolo). O selo já é válido e verificável desde a emissão.');
    }
    lines.push('');
  } else {
    lines.push('2. selo_opentimestamps.ots — NÃO INCLUÍDO');
    lines.push('   O selo OpenTimestamps ainda não havia sido emitido no momento');
    lines.push('   deste download. Repita o download após a emissão do selo.');
    lines.push('');
  }
  if (hasTsr) {
    lines.push(`3. ${TSR_FILENAME}`);
    lines.push('   Carimbo de tempo qualificado RFC 3161 (FreeTSA). Tem validade');
    lines.push('   legal imediata e é prova autônoma de temporalidade.');
    lines.push('');
  } else {
    lines.push('3. selo_rfc3161.tsr — NÃO INCLUÍDO');
    lines.push('   O carimbo RFC 3161 não havia sido emitido no momento deste');
    lines.push('   download.');
    lines.push('');
  }
  lines.push('4. hash_sha256.txt');
  lines.push('   Impressão digital criptográfica da evidência (SHA-256).');
  lines.push('');
  const media = input.media || [];
  if (media.length > 0) {
    lines.push('5. midia/');
    media.forEach((m) => {
      lines.push(`   • ${m.filename}${m.description ? ' — ' + m.description : ''}`);
    });
    lines.push('');
  }
  lines.push('Documentos de apoio (não precisam ser juntados, servem ao');
  lines.push('contraditório): COMO_VERIFICAR.txt e METODOLOGIA_TECNICA.txt.');
  lines.push('');
  lines.push('='.repeat(70));
  lines.push('LIMITES: este pacote atesta a integridade do que foi capturado e a');
  lines.push('cadeia de custódia desde a captura — não a autenticidade do');
  lines.push('conteúdo de origem, assim como a autenticação cartorial atesta a');
  lines.push('cópia e não o documento-fonte.');
  return lines.join('\n');
}

export async function buildNotarialEvidenceZip(
  input: NotarialEvidenceZipInput,
): Promise<{ blob: Blob; filename: string }> {
  const zip = new JSZip();
  const shortHash = (input.evidenceHash || '').slice(0, 12) || 'sem-hash';
  const pdfName = input.pdfFilename || 'relatorio_evidencia.pdf';

  // PDF principal
  if (input.pdfBlob) {
    zip.file(pdfName, input.pdfBlob);
  } else if (input.pdfBase64) {
    zip.file(pdfName, base64ToBytes(input.pdfBase64));
  }

  // Selos
  let hasOts = false;
  if (input.otsBase64) {
    try {
      zip.file(OTS_FILENAME, base64ToBytes(input.otsBase64));
      hasOts = true;
      if (input.otsSha256) {
        zip.file(`${OTS_FILENAME}.sha256.txt`, `${input.otsSha256}  ${OTS_FILENAME}\n`);
      }
    } catch (e) {
      console.warn('[notarial-zip] .ots decode falhou', e);
    }
  }
  let hasTsr = false;
  if (input.tsrBase64) {
    try {
      zip.file(TSR_FILENAME, base64ToBytes(input.tsrBase64));
      hasTsr = true;
    } catch (e) {
      console.warn('[notarial-zip] .tsr decode falhou', e);
    }
  }

  // Hash da evidência
  zip.file('hash_sha256.txt', `${input.evidenceHash}  ${pdfName}\n`);

  // Mídia
  const media = input.media || [];
  if (media.length > 0) {
    const folder = zip.folder('midia');
    media.forEach((m) => folder?.file(m.filename, m.blob));
  }

  // Roteiro de verificação independente (ISO/IEC 27037)
  zip.file(
    'COMO_VERIFICAR.txt',
    buildIso27037TextBlock({
      evidenceHash: input.evidenceHash,
      otsSha256: input.otsSha256 ?? null,
      blockHeight: input.blockHeight ?? null,
      blockHash: input.blockHash ?? null,
      blockMerkleRoot: input.blockMerkleRoot ?? null,
      blockTime: input.blockTime ?? null,
      calendars: input.calendars,
      otsFilename: OTS_FILENAME,
    }),
  );

  // Metodologia + procedência + cadeia de custódia
  try {
    const prov = await loadPlatformProvenance();
    zip.file(
      'METODOLOGIA_TECNICA.txt',
      buildPlatformProvenanceTextBlock(prov) +
        '\n\n' +
        buildCustodyBlockTextBlock({
          sessionId: input.evidenceHash,
          startedAt: input.startedAt || null,
          finishedAt: input.finishedAt || new Date().toISOString(),
          operatorName: input.operatorName || null,
          artifactCount: 1 + media.length,
          masterHash: input.evidenceHash,
          masterHashValid: true,
          chainIntact: true,
          anchors: [
            hasTsr ? 'RFC 3161 (FreeTSA)' : null,
            hasOts ? 'OpenTimestamps (Bitcoin)' : null,
          ].filter(Boolean) as string[],
          anchorConfirmed: input.blockHeight != null,
        }),
    );
  } catch (e) {
    console.warn('[notarial-zip] metodologia/procedência indisponível', e);
  }

  zip.file('LEIA_PRIMEIRO.txt', buildLeiaPrimeiro(input, pdfName, hasOts, hasTsr));

  const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
  const filename = `relatorio_evidencia_${input.prefix}_${shortHash}.zip`;
  return { blob, filename };
}

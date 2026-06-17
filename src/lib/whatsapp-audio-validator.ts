/**
 * WhatsApp Audio Validator
 * Determinístico, 100% client-side, sem IA.
 *
 * Responde: "esse arquivo de áudio tem assinatura técnica compatível
 * com um áudio enviado originalmente pelo WhatsApp?"
 *
 * NÃO afirma autoria de voz nem identifica falante. Apenas valida o
 * container/codec contra o perfil técnico que o WhatsApp produz:
 *   - Container: OGG (magic "OggS") encapsulando Opus
 *   - Codec: Opus (header "OpusHead")
 *   - Sample rate: 16000 Hz (typical) ou 48000 Hz (WhatsApp atual)
 *   - Canais: 1 (mono)
 *   - Sem tags ID3/metadata extra
 */

export type WaAudioVerdict = 'compativel' | 'reencodado' | 'inconclusivo';

export interface WaAudioAnalysis {
  verdict: WaAudioVerdict;
  container: 'ogg' | 'mp3' | 'mp4-aac' | 'wav' | 'desconhecido';
  codec: 'opus' | 'mp3' | 'aac' | 'pcm' | 'desconhecido';
  sampleRate: number | null;
  channels: number | null;
  hasId3: boolean;
  hasOpusHead: boolean;
  fileSize: number;
  reasons: string[]; // razões objetivas que sustentam o veredito
  humanGuidance: string; // mensagem acionável para o operador
}

function buildHumanGuidance(
  verdict: WaAudioVerdict,
  container: WaAudioAnalysis['container'],
): string {
  if (verdict === 'compativel') {
    return 'Assinatura técnica compatível com áudio enviado direto pelo WhatsApp. Pode prosseguir para o laudo.';
  }
  if (verdict === 'reencodado') {
    const origem =
      container === 'mp3' ? 'MP3 — provavelmente passou por e-mail, Telegram ou conversor.'
      : container === 'mp4-aac' ? 'MP4/M4A (AAC) — comum quando salvo via app de gravador ou iCloud.'
      : container === 'wav' ? 'WAV cru — comum quando passou por edição em desktop.'
      : 'formato não-WhatsApp.';
    return (
      `Este arquivo NÃO veio direto do WhatsApp (${origem}). ` +
      'Volte ao celular de origem, segure o áudio na conversa → Compartilhar → "Salvar em Arquivos" (iOS) ou "Drive/Files" (Android), e suba aqui o arquivo .opus/.ogg sem renomear. ' +
      'Não encaminhe pelo próprio WhatsApp nem por e-mail/Telegram.'
    );
  }
  return (
    'Não foi possível confirmar a assinatura WhatsApp deste arquivo. ' +
    'Verifique se ele realmente foi obtido via Compartilhar → Salvar em Arquivos a partir do app oficial, sem renomear extensão nem converter.'
  );
}

/**
 * Lê os primeiros bytes do arquivo e identifica container + codec
 * sem dependências externas. Combina com Web Audio API para sample rate.
 */
export async function analyzeWhatsAppAudio(file: File): Promise<WaAudioAnalysis> {
  const reasons: string[] = [];
  const head = new Uint8Array(await file.slice(0, 256).arrayBuffer());

  // Detectar ID3 (MP3 com tags)
  const hasId3 = head[0] === 0x49 && head[1] === 0x44 && head[2] === 0x33; // "ID3"
  if (hasId3) reasons.push('Tag ID3 presente — incompatível com áudio cru do WhatsApp.');

  // Detectar magic numbers
  let container: WaAudioAnalysis['container'] = 'desconhecido';
  let codec: WaAudioAnalysis['codec'] = 'desconhecido';
  let hasOpusHead = false;

  // OGG: "OggS" em offset 0
  if (head[0] === 0x4f && head[1] === 0x67 && head[2] === 0x67 && head[3] === 0x53) {
    container = 'ogg';
    // Procurar "OpusHead" nos primeiros 128 bytes
    const sig = 'OpusHead';
    for (let i = 0; i < head.length - sig.length; i++) {
      let ok = true;
      for (let j = 0; j < sig.length; j++) {
        if (head[i + j] !== sig.charCodeAt(j)) { ok = false; break; }
      }
      if (ok) { hasOpusHead = true; codec = 'opus'; break; }
    }
    if (!hasOpusHead) reasons.push('Container OGG porém sem header OpusHead.');
  } else if (hasId3 || (head[0] === 0xff && (head[1] & 0xe0) === 0xe0)) {
    container = 'mp3';
    codec = 'mp3';
    reasons.push('Arquivo é MP3 — WhatsApp não envia MP3 nativamente; provável reencode.');
  } else if (head[4] === 0x66 && head[5] === 0x74 && head[6] === 0x79 && head[7] === 0x70) {
    // "ftyp" em offset 4 → MP4/M4A
    container = 'mp4-aac';
    codec = 'aac';
    reasons.push('Arquivo é MP4/M4A (AAC) — WhatsApp usa Opus; provável reencode (iOS Voice Memo etc.).');
  } else if (head[0] === 0x52 && head[1] === 0x49 && head[2] === 0x46 && head[3] === 0x46) {
    container = 'wav';
    codec = 'pcm';
    reasons.push('Arquivo é WAV (PCM cru) — WhatsApp não distribui WAV.');
  }

  // Sample rate / canais via Web Audio API (sem decodificar tudo se possível)
  let sampleRate: number | null = null;
  let channels: number | null = null;
  try {
    const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
    const buf = await ctx.decodeAudioData(await file.arrayBuffer());
    sampleRate = buf.sampleRate;
    channels = buf.numberOfChannels;
    await ctx.close();
  } catch {
    reasons.push('Falha ao decodificar — codec exótico ou arquivo corrompido.');
  }

  // Avaliação WhatsApp:
  //   - WhatsApp atual: Opus em OGG, mono. Sample rate 16k (legado) ou 48k (PTT moderno).
  if (channels !== null && channels > 1) {
    reasons.push(`Áudio em ${channels} canais — WhatsApp envia sempre mono.`);
  }
  if (sampleRate !== null && sampleRate !== 16000 && sampleRate !== 48000) {
    reasons.push(`Sample rate ${sampleRate} Hz fora do padrão WhatsApp (16000 ou 48000 Hz).`);
  }

  // Veredito
  let verdict: WaAudioVerdict;
  const isOpusOggMono = container === 'ogg' && codec === 'opus' && channels === 1
    && (sampleRate === 16000 || sampleRate === 48000) && !hasId3;

  if (isOpusOggMono) {
    verdict = 'compativel';
    if (reasons.length === 0) {
      reasons.push('Container OGG + codec Opus + mono + sample rate WhatsApp + sem tags.');
    }
  } else if (container === 'mp3' || container === 'mp4-aac' || container === 'wav' || hasId3) {
    verdict = 'reencodado';
  } else if (container === 'ogg' && codec === 'opus') {
    verdict = 'inconclusivo';
    reasons.push('Opus/OGG mas com parâmetros divergentes do padrão WhatsApp.');
  } else {
    verdict = 'inconclusivo';
  }

  return {
    verdict,
    container,
    codec,
    sampleRate,
    channels,
    hasId3,
    hasOpusHead,
    fileSize: file.size,
    reasons,
    humanGuidance: buildHumanGuidance(verdict, container),
  };
}

export function verdictLabel(v: WaAudioVerdict): string {
  switch (v) {
    case 'compativel': return 'Compatível com WhatsApp';
    case 'reencodado': return 'Re-encodado (perdeu integridade técnica)';
    case 'inconclusivo': return 'Inconclusivo';
  }
}

export function verdictColor(v: WaAudioVerdict): string {
  switch (v) {
    case 'compativel': return 'bg-green-500/15 text-green-500 border-green-500/30';
    case 'reencodado': return 'bg-amber-500/15 text-amber-500 border-amber-500/30';
    case 'inconclusivo': return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

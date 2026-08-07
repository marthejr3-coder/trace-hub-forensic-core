/**
 * METODOLOGIA TÉCNICA DE COLETA E PRESERVAÇÃO DA EVIDÊNCIA DIGITAL
 * ================================================================
 * Fonte única da "assinatura técnica" do Trace Hub — os 10 itens da
 * metodologia que devem aparecer em TODO relatório (Capture Link, Ata
 * Notarial, Evidence Cripto, WhatsApp, E-mail, Redes Sociais, Cadeia de
 * Custódia), logo após a identificação da sessão/solicitante e antes da
 * primeira evidência.
 *
 * Regras de honestidade técnica aplicadas (não alterar sem revisão jurídica):
 *  • SHA-256 é sempre calculado; SHA-512 é espelho e, no dispositivo do
 *    declarante, pode ser pulado em arquivos grandes (ver hashFileDual em
 *    forensic-hash.ts) — nesse caso o servidor recalcula.
 *  • O duplo cálculo cliente × servidor só existe no Capture Link. Em
 *    captura assistida o hash nasce no ambiente controlado do servidor.
 *  • Ancoragem Bitcoin pode estar PENDENTE no momento da emissão — nunca
 *    afirmar anterioridade confirmada sem altura de bloco.
 *  • Limites de escopo e limite do verificador RFC 3161 vêm de
 *    legal-retention.ts (redação canônica única).
 */

import { LIMITES_ESCOPO_CLAUSE, TSR_VALIDATION_NOTE } from '@/lib/legal-retention';

export type AcquisitionMode = 'capture_link' | 'assistida';

export interface MethodologyOptions {
  /** Como a evidência entrou no sistema. */
  acquisitionMode: AcquisitionMode;
  /** SHA-512 espelho efetivamente presente neste relatório. */
  hasSha512?: boolean;
  /** Âncoras temporais efetivamente aplicadas a esta evidência. */
  anchors?: {
    rfc3161?: boolean;
    opentimestamps?: boolean;
    /** true somente quando há altura de bloco Bitcoin confirmada. */
    bitcoinConfirmed?: boolean;
  };
  /** Artefatos preservados neste relatório (só lista o que existe). */
  preservedArtifacts?: {
    html?: boolean;
    screenshot?: boolean;
    video?: boolean;
    httpHeaders?: boolean;
    dns?: boolean;
    rdap?: boolean;
    tls?: boolean;
  };
}

export const METHODOLOGY_TITLE =
  'Metodologia Técnica de Coleta e Preservação da Evidência Digital';


const CUSTODY_FIELDS = [
  'timestamps',
  'IP',
  'User Agent',
  'fingerprint do navegador',
  'sistema operacional',
  'informações de hardware',
  'metadados intrínsecos do arquivo',
  'EXIF',
  'MIME Type declarado × detectado',
  'assinatura mágica (magic bytes)',
  'tamanho',
  'resolução',
  'informações de sessão',
];

const COMPLIANCE = [
  'ISO/IEC 27037:2012 — identificação, coleta, aquisição e preservação de evidências digitais',
  'FIPS PUB 180-4 — Secure Hash Standard (SHA-256 / SHA-512)',
  'RFC 3161 — Time-Stamp Protocol',
  'OpenTimestamps Protocol (opentimestamps.org)',
  'MP 2.200-2/2001, art. 10, §2º — meios eletrônicos de comprovação documental',
  'CPC, arts. 411, II e 422 — natureza documental da prova digital',
  'CPP, art. 158-A e seguintes — por analogia aos princípios de cadeia de custódia',
];

const NOT_PROVEN = [
  'autoria intelectual do conteúdo',
  'veracidade dos fatos retratados',
  'inexistência de eventual manipulação anterior ao momento da coleta',
  'identidade civil de quem produziu originalmente o arquivo, salvo quando demonstrada por outros elementos probatórios',
];

const PROVEN = [
  'integridade da evidência desde sua aquisição',
  'preservação da cadeia de custódia',
  'anterioridade temporal (nos limites das âncoras efetivamente confirmadas)',
  'rastreabilidade da coleta',
  'ausência de alteração após a captura',
];

function artifactList(a: MethodologyOptions['preservedArtifacts']): string[] {
  if (!a) return [];
  const out: string[] = [];
  if (a.html) out.push('HTML original');
  if (a.screenshot) out.push('screenshot');
  if (a.video) out.push('vídeo integral da navegação');
  if (a.httpHeaders) out.push('cabeçalhos HTTP e status HTTP');
  if (a.dns) out.push('registros DNS');
  if (a.rdap) out.push('dados RDAP do domínio');
  if (a.tls) out.push('certificados SSL/TLS');
  return out;
}

function hashParagraph(opts: MethodologyOptions): string {
  const algos = opts.hasSha512
    ? 'SHA-256 (identificador primário) e SHA-512 (verificação espelho)'
    : 'SHA-256 (identificador primário)';
  if (opts.acquisitionMode === 'capture_link') {
    return (
      `Antes de qualquer armazenamento definitivo o sistema calcula ${algos}. Os hashes são ` +
      'calculados inicialmente no próprio dispositivo do declarante e recalculados pelo servidor ' +
      'após a transmissão; a coincidência integral dos valores demonstra que não houve alteração ' +
      'durante o transporte. O SHA-512 client-side pode ser omitido em arquivos de grande volume ' +
      'por limitação de memória do dispositivo — nessa hipótese ele é calculado pelo servidor e o ' +
      'confronto cliente × servidor permanece válido para o SHA-256.'
    );
  }
  return (
    `Imediatamente após a aquisição dos artefatos produzidos na sessão controlada, o sistema ` +
    `calcula ${algos} no ambiente do servidor, antes de qualquer armazenamento definitivo. Nesta ` +
    'modalidade não há hash de origem no dispositivo de terceiro: o hash nasce no ambiente ' +
    'controlado da Central Forense e é o valor submetido às âncoras temporais.'
  );
}

function anchorParagraph(opts: MethodologyOptions): string {
  const a = opts.anchors || {};
  const used: string[] = [];
  if (a.rfc3161) used.push('RFC 3161 (Time Stamp Authority — FreeTSA)');
  if (a.opentimestamps) used.push('OpenTimestamps');
  if (a.opentimestamps) used.push('ancoragem em blockchain Bitcoin (via OpenTimestamps)');
  const base = used.length
    ? `Após a conclusão da coleta o hash criptográfico é submetido a mecanismos independentes de ` +
      `comprovação temporal: ${used.join('; ')}.`
    : 'Após a conclusão da coleta o hash criptográfico fica disponível para submissão a mecanismos ' +
      'independentes de comprovação temporal (RFC 3161 e OpenTimestamps).';
  const pending =
    a.opentimestamps && !a.bitcoinConfirmed
      ? ' No momento da emissão deste relatório a agregação em bloco Bitcoin ainda NÃO estava ' +
        'confirmada: entrega-se o artefato .ots, cuja confirmação e altura de bloco podem ser ' +
        'verificadas posteriormente por qualquer terceiro, sem intervenção do Trace Hub. Enquanto ' +
        'pendente, este documento não afirma anterioridade ancorada em Bitcoin.'
      : a.bitcoinConfirmed
        ? ' A altura e o hash do bloco Bitcoin constam nas seções de ancoragem, permitindo ' +
          'demonstrar que a evidência já existia em momento anterior ao da emissão deste relatório, ' +
          'independentemente da infraestrutura do Trace Hub.'
        : '';
  return base + pending;
}

/**
 * Linhas [rótulo, valor] para renderização em tabelas de laudo
 * (kv() do notarial-text-pdf ou autoTable do jsPDF).
 * Rótulos no formato "--- X ---" com valor vazio são divisores de seção.
 */
export function buildMethodologyRows(opts: MethodologyOptions): [string, string][] {
  const rows: [string, string][] = [];
  const artifacts = artifactList(opts.preservedArtifacts);

  rows.push([`--- ${METHODOLOGY_TITLE.toUpperCase()} ---`, '']);

  rows.push([
    '1. Objetivo',
    'Documentar, de forma técnica e reproduzível, o procedimento empregado pelo Trace Hub para ' +
      'identificação, aquisição, preservação e verificação da evidência digital, garantindo ' +
      'rastreabilidade integral da cadeia de custódia desde a coleta até a emissão deste documento. ' +
      'A metodologia baseia-se na ISO/IEC 27037:2012, complementada por verificação criptográfica de ' +
      'integridade, registro temporal independente e documentação automatizada das operações.',
  ]);




  rows.push([
    '3.1 Etapa 1 — Inicialização',
    'Criação de sessão única de coleta identificada por UUID criptograficamente aleatório, com ' +
      'registro de horário inicial, identificador da sessão, operador (quando aplicável) e ' +
      'parâmetros de captura.',
  ]);
  rows.push([
    '3.2 Etapa 2 — Aquisição',
    opts.acquisitionMode === 'capture_link'
      ? 'Modalidade Capture Link: envio direto pelo dispositivo do declarante. O arquivo original ' +
        'não sofre alteração; a coleta preserva o arquivo exatamente como produzido pelo dispositivo ' +
        'de origem, sempre que tecnicamente possível.'
      : 'Modalidade Captura Assistida: coleta realizada pelo operador da Central Forense em sessão ' +
        'controlada. O artefato original não sofre alteração após a aquisição.',
  ]);
  rows.push(['3.3 Etapa 3 — Verificação imediata de integridade', hashParagraph(opts)]);

  rows.push([
    '4. Preservação da cadeia de custódia',
    'Cada evidência recebe identificador único. Durante o processamento são registrados ' +
      'automaticamente, conforme disponibilidade técnica: ' +
      CUSTODY_FIELDS.join(', ') +
      '.' +
      (artifacts.length
        ? ` Neste relatório foram ainda preservados: ${artifacts.join(', ')}.`
        : ''),
  ]);

  rows.push([
    '5. Integridade criptográfica',
    'A integridade é protegida por funções unidirecionais do padrão FIPS 180-4: o SHA-256 é o ' +
      'identificador primário da evidência' +
      (opts.hasSha512 ? ' e o SHA-512 atua como verificação espelho' : '') +
      '. A conferência pode ser feita com qualquer implementação compatível.',
  ]);

  rows.push(['6. Ancoragem temporal independente', anchorParagraph(opts)]);

  rows.push([
    '7. Auditabilidade, repetibilidade e reprodutibilidade',
    'Algoritmos, hashes, metadados, identificadores, comandos de validação e artefatos de ancoragem ' +
      'constam deste relatório. Os procedimentos são determinísticos: mantidos os mesmos arquivos de ' +
      'entrada, qualquer especialista recalcula os hashes e valida os carimbos temporais com ' +
      'ferramentas públicas, sem utilizar a plataforma Trace Hub.',
  ]);


  // Não usar U+2713 (✓): as fontes padrão do jsPDF são WinAnsi e renderizam glifo inválido.
  rows.push(['9.1 Este relatório comprova', PROVEN.map((p) => `[OK] ${p}`).join('\n')]);

  rows.push(['9.2 Este relatório NÃO comprova', NOT_PROVEN.map((p) => `• ${p}`).join('\n')]);
  rows.push(['9.3 Limites de escopo', LIMITES_ESCOPO_CLAUSE]);
  if (opts.anchors?.rfc3161) {
    rows.push(['9.4 Limite do verificador RFC 3161', TSR_VALIDATION_NOTE]);
  }

  rows.push(['10. Conformidade técnica', COMPLIANCE.map((c) => `• ${c}`).join('\n')]);

  return rows;
}

/**
 * Mesma seção em texto puro, para README.txt dos pacotes forenses (ZIP).
 */
export function buildMethodologyTextBlock(opts: MethodologyOptions): string {
  const rows = buildMethodologyRows(opts);
  const lines: string[] = [
    METHODOLOGY_TITLE.toUpperCase(),
    '='.repeat(70),
    '',
  ];
  for (const [label, value] of rows) {
    if (!value) continue; // divisor
    lines.push(label);
    lines.push('-'.repeat(Math.min(70, label.length + 4)));
    for (const part of value.split('\n')) {
      lines.push(...wrap(part, 74).map((l) => `  ${l}`));
    }
    lines.push('');
  }
  return lines.join('\n');
}

function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  const out: string[] = [];
  let cur = '';
  for (const w of words) {
    if (!cur.length) cur = w;
    else if (cur.length + 1 + w.length <= width) cur += ` ${w}`;
    else {
      out.push(cur);
      cur = w;
    }
  }
  if (cur.length) out.push(cur);
  return out.length ? out : [''];
}

/**
 * forensic-report-copy.ts
 * =======================
 * Fonte única dos textos institucionais, didáticos e de esclarecimento que
 * acompanham TODOS os relatórios técnicos do Trace Hub (PDF e README.txt de ZIP).
 *
 * Regras:
 *  • Nenhum destes textos altera hash, timestamp, comando ou fundamento jurídico.
 *  • Horário original (UTC) NUNCA é substituído — a conversão local é adicional.
 *  • Não usar emojis nem glifos fora do Latin-1: os PDFs usam fontes WinAnsi.
 */

export const INSTITUTIONAL_INTRO =
  'O Trace Hub adota metodologia de aquisição de evidências digitais baseada na ISO/IEC 27037:2012, ' +
  'com verificação criptográfica de integridade, documentação automatizada da cadeia de custódia, ' +
  'selo temporal RFC 3161 e ancoragem pública em Blockchain Bitcoin. ' +
  'A evidência resultante é auditável, reproduzível e verificável por terceiros independentes, sem ' +
  'depender da infraestrutura do Trace Hub.';

export const INDEPENDENT_VERIFICATION_INTRO =
  'A autenticidade da ancoragem temporal pode ser confirmada utilizando implementações ' +
  'independentes entre si. A coincidência dos resultados demonstra a consistência da prova e ' +
  'elimina dependência exclusiva da infraestrutura do Trace Hub.';

export const TIME_REFERENCE_NOTE =
  'Os registros de RFC 3161, OpenTimestamps e Blockchain Bitcoin utilizam o padrão UTC. Todos os ' +
  'marcos temporais são apresentados com o valor original em UTC, exatamente como registrado pela ' +
  'fonte, seguido da conversão para o fuso horário da coleta entre parênteses, apenas para ' +
  'facilitar a leitura. O valor original em UTC nunca é substituído, arredondado ou reescrito; a ' +
  'diferença entre os horários decorre exclusivamente da conversão de fuso.';

export const BLOCKCHAIN_EXPLANATION =
  'Após a emissão do selo temporal RFC 3161, o hash da evidência é submetido ao OpenTimestamps para ' +
  'ancoragem na Blockchain Bitcoin, cuja confirmação depende da rede e ocorre normalmente entre 1 e ' +
  '6 horas. Em situações de urgência o relatório pode ser emitido antes dessa confirmação. ' +
  'A pendência da ancoragem não afeta a integridade da evidência, a cadeia de custódia, os hashes ' +
  'criptográficos nem a metodologia empregada — a confirmação posterior apenas acrescenta camada ' +
  'pública de transparência e verificabilidade independente.';

export const STJ_COMPLIANCE_TITLE = 'Conformidade Técnica com a Jurisprudência do STJ';

export const STJ_COMPLIANCE_PARAGRAPHS: string[] = [
  'A jurisprudência do Superior Tribunal de Justiça, sistematizada na Jurisprudência em Teses n. 281 ' +
    '(Direito Penal e Processual Penal em Ambiente Digital), reconhece como elementos essenciais à ' +
    'admissibilidade da prova digital a preservação da cadeia de custódia e a possibilidade de exame ' +
    'técnico independente, admitindo as funções hash como mecanismo certificador da identidade entre ' +
    'o material coletado e o material examinado (princípio da mesmidade).',
  'A Corte Especial do STJ, no Inq 1.674/DF (Rel. Min. Nancy Andrighi, j. mai/2026), reconhece a autenticação de evidências digitais por meio de funções hash ' +
    'como mecanismo apto a preservar a integridade e a auditabilidade de conteúdos imateriais, ' +
    'exigindo-se auditabilidade, repetibilidade, reprodutibilidade e justificabilidade dos ' +
    'procedimentos, com documentação adequada da cadeia de custódia.',
  'Correspondência técnica: a integridade é assegurada por SHA-256 e SHA-512 (FIPS 180-4); a ' +
    'mesmidade é demonstrada pela comparação dos hashes cliente x servidor; a cadeia de custódia é ' +
    'registrada automaticamente por sessão única; a auditabilidade decorre da publicação dos ' +
    'algoritmos, hashes e comandos de verificação neste relatório; a repetibilidade decorre do ' +
    'recálculo determinístico dos hashes; a reprodutibilidade é possível com ferramentas públicas ' +
    'independentes; e a anterioridade é demonstrada por RFC 3161, OpenTimestamps e Blockchain ' +
    'Bitcoin. A verificação da integridade não depende de confiança na plataforma Trace Hub.',
];

export const EXHIBITOR_RESPONSIBILITY_TITLE = 'Responsabilização do Exibidor da Prova';

export const EXHIBITOR_RESPONSIBILITY_TEXT =
  'Quando a evidência é apresentada por terceiro (vítima, testemunha, advogado ou representante ' +
  'legal), o declarante assume responsabilidade pelas informações declaradas. O Trace Hub registra a ' +
  'declaração e os elementos técnicos disponíveis no momento da coleta, sem emitir juízo sobre a ' +
  'veracidade material do conteúdo. Controvérsias quanto à autoria, à origem ou à autenticidade ' +
  'material permanecem sujeitas ao contraditório e a eventual perícia determinada pelo Juízo.';

/** Etapas do fluxograma da metodologia. */
export const METHODOLOGY_FLOW_STEPS: string[] = [
  'Aquisição da Evidência',
  'Hash SHA-256 / SHA-512 (Cliente)',
  'Transmissão Segura (TLS)',
  'Hash SHA-256 / SHA-512 (Servidor)',
  'Comparação de Integridade',
  'Registro Automático da Cadeia de Custódia',
  'Selo Temporal RFC 3161',
  'OpenTimestamps',
  'Blockchain Bitcoin',
  'Relatório Técnico Final',
];

export const EXEC_SUMMARY_TITLE = 'Resumo Executivo';

export const EXEC_SUMMARY_NOTE =
  'Este quadro sintetiza, em linguagem acessível, os elementos técnicos que sustentam a robustez ' +
  'da evidência documentada nas páginas seguintes. Os detalhes, hashes e comandos de conferência ' +
  'constam nas seções técnicas do relatório.';

export type ExecStatus = 'ok' | 'pending' | 'na';

export interface ExecSummaryFlags {
  integrity?: boolean;
  custody?: boolean;
  clientServerMatch?: ExecStatus;
  rfc3161?: ExecStatus;
  bitcoin?: ExecStatus;
  originalsPreserved?: boolean;
  metadata?: boolean;
  auditable?: boolean;
  iso27037?: boolean;
}

export function buildExecSummaryItems(
  flags: ExecSummaryFlags,
): { status: ExecStatus; label: string }[] {
  const b = (v: boolean | undefined): ExecStatus => (v === false ? 'na' : 'ok');
  return [
    { status: b(flags.integrity), label: 'Integridade Confirmada' },
    { status: b(flags.custody), label: 'Cadeia de Custódia Preservada' },
    { status: flags.clientServerMatch ?? 'na', label: 'Hash Cliente = Servidor' },
    { status: flags.rfc3161 ?? 'na', label: 'Selo RFC 3161 Emitido' },
    { status: flags.bitcoin ?? 'pending', label: 'Blockchain Bitcoin' },
    { status: b(flags.originalsPreserved), label: 'Arquivos Originais Preservados' },
    { status: b(flags.metadata), label: 'Metadados Extraídos' },
    { status: b(flags.auditable), label: 'Evidência Auditável' },
    { status: b(flags.iso27037), label: 'ISO/IEC 27037:2012' },
  ];
}

export const ANCHORING_STATUS_TITLE = 'Status da Ancoragem';

export interface AnchoringStatusInfo {
  sha256?: boolean;
  sha512?: boolean;
  clientServer?: boolean;
  custody?: boolean;
  rfc3161?: boolean;
  opentimestamps?: boolean;
  bitcoinBlockHeight?: number | null;
  blockHash?: string | null;
  blockTimeUtc?: string | null;
}

export function buildAnchoringStatusLines(
  info: AnchoringStatusInfo,
): { status: ExecStatus; label: string }[] {
  const s = (v: boolean | undefined): ExecStatus => (v ? 'ok' : 'na');
  const btcOk = !!info.bitcoinBlockHeight;
  return [
    { status: s(info.sha256), label: 'Hash SHA-256' },
    { status: s(info.sha512), label: 'Hash SHA-512' },
    { status: s(info.clientServer), label: 'Integridade Cliente x Servidor' },
    { status: s(info.custody), label: 'Cadeia de Custódia' },
    { status: s(info.rfc3161), label: 'RFC 3161' },
    { status: s(info.opentimestamps), label: 'OpenTimestamps' },
    {
      status: btcOk ? 'ok' : 'pending',
      label: btcOk
        ? `Blockchain Bitcoin Confirmada — bloco #${info.bitcoinBlockHeight}`
        : 'Blockchain Bitcoin — aguardando confirmação da rede',
    },
  ];
}

// ─── Duplo horário (UTC original + conversão local) ───────────────────────────

export const DEFAULT_TZ = 'America/Sao_Paulo';

export function resolveTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || DEFAULT_TZ;
  } catch {
    return DEFAULT_TZ;
  }
}

function fmt(d: Date, tz: string): string {
  try {
    return new Intl.DateTimeFormat('pt-BR', {
      timeZone: tz,
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(d);
  } catch {
    return d.toISOString();
  }
}

/**
 * Apresenta o marco temporal em duplicidade, sem jamais substituir o valor
 * original em UTC. Retorna "DD/MM/AAAA HH:MM:SS UTC (DD/MM/AAAA HH:MM:SS <tz>)".
 */
export function formatDualTime(
  value?: string | number | Date | null,
  tz: string = resolveTimeZone(),
): string {
  if (value == null || value === '') return 'Não informado';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  const utc = fmt(d, 'UTC');
  const local = fmt(d, tz);
  if (utc === local) return `${utc} UTC`;
  return `${utc} UTC (${local} ${tz})`;
}

// ─── Versões em texto puro para README.txt dos pacotes ZIP ────────────────────

function wrapTxt(text: string, width = 74): string[] {
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

function block(title: string, body: string | string[]): string {
  const lines: string[] = [title.toUpperCase(), '='.repeat(Math.min(70, title.length + 4)), ''];
  const parts = Array.isArray(body) ? body : [body];
  for (const p of parts) lines.push(...wrapTxt(p));
  lines.push('');
  return lines.join('\n');
}

function mark(status: ExecStatus): string {
  return status === 'ok' ? '[OK]' : status === 'pending' ? '[..]' : '[ -]';
}

export interface ReportCopyTextOptions {
  execSummary?: ExecSummaryFlags;
  anchoringStatus?: AnchoringStatusInfo;
}

/** Blocos didáticos em texto puro, para o topo dos README.txt dos pacotes forenses. */
export function buildReportCopyTextBlocks(opts: ReportCopyTextOptions = {}): string {
  const out: string[] = [];

  if (opts.execSummary) {
    const items = buildExecSummaryItems(opts.execSummary)
      .map((i) => `  ${mark(i.status)} ${i.label}`)
      .join('\n');
    out.push(
      [EXEC_SUMMARY_TITLE.toUpperCase(), '='.repeat(24), '', items, '', ...wrapTxt(EXEC_SUMMARY_NOTE), ''].join('\n'),
    );
  }

  out.push(block('Apresentação institucional', INSTITUTIONAL_INTRO));
  out.push(
    block(
      'Fluxo da evidência',
      METHODOLOGY_FLOW_STEPS.map((s, i) => `${String(i + 1).padStart(2, '0')}. ${s}`),
    ),
  );


  if (opts.anchoringStatus) {
    const lines = buildAnchoringStatusLines(opts.anchoringStatus).map((i) => `  ${mark(i.status)} ${i.label}`);
    const extra: string[] = [];
    if (opts.anchoringStatus.bitcoinBlockHeight) {
      extra.push('', `Bloco: #${opts.anchoringStatus.bitcoinBlockHeight}`);
      if (opts.anchoringStatus.blockHash) extra.push(`Block hash: ${opts.anchoringStatus.blockHash}`);
      if (opts.anchoringStatus.blockTimeUtc)
        extra.push(`Horário do bloco: ${formatDualTime(opts.anchoringStatus.blockTimeUtc)}`);
    }
    out.push(
      [
        ANCHORING_STATUS_TITLE.toUpperCase(),
        '='.repeat(24),
        '',
        ...lines,
        ...extra,
        '',
      ].join('\n'),
    );
  }

  out.push(block('Verificação independente', INDEPENDENT_VERIFICATION_INTRO));
  out.push(block('Referência de horário', TIME_REFERENCE_NOTE));
  out.push(block('Esclarecimento sobre a Blockchain', BLOCKCHAIN_EXPLANATION));
  out.push(block(STJ_COMPLIANCE_TITLE, STJ_COMPLIANCE_PARAGRAPHS));
  out.push(block(EXHIBITOR_RESPONSIBILITY_TITLE, EXHIBITOR_RESPONSIBILITY_TEXT));

  return out.join('\n');
}

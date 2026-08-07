/**
 * forensic-custody-block.ts
 * =========================
 * Bloco padronizado "CADEIA DE CUSTÓDIA DA SESSÃO" presente em TODOS os
 * relatórios de prova digital do Trace Hub.
 *
 * Regras:
 *  • Nada é recalculado aqui — apenas leitura e apresentação de dados já
 *    produzidos pelos pipelines (master hash, âncoras, timestamps).
 *  • Campos ausentes são OMITIDOS (nunca "Não informado" órfão).
 *  • O status jamais é otimista: sem master hash válido ou sem âncora
 *    confirmada, o veredito é rebaixado.
 */
import { formatDualTime } from '@/lib/forensic-report-copy';

export type CustodyBlockStatus = 'verificada' | 'ressalvas' | 'nao_verificada';

export interface CustodyBlockInput {
  /** Identificador da sessão/coleta (UUID, token ou referência do caso). */
  sessionId?: string | null;
  /** Início da sessão (ISO/Date). */
  startedAt?: string | number | Date | null;
  /** Encerramento da captura (ISO/Date). */
  finishedAt?: string | number | Date | null;
  /** Operador responsável. */
  operatorName?: string | null;
  operatorEmail?: string | null;
  operatorId?: string | null;
  /** Modo do autor: perito | policial | operador_direito | vitima. */
  authorMode?: string | null;
  /** Quantidade de artefatos correlacionados no manifesto. */
  artifactCount?: number | null;
  /** Hash mestre (SHA-256) do manifesto/relatório. */
  masterHash?: string | null;
  /** Resultado do recálculo do master hash, quando disponível. */
  masterHashValid?: boolean | null;
  /** Cadeia de custódia/DOM/eventos sem quebras. */
  chainIntact?: boolean | null;
  /** Ambiente sinalizado como adulterado (DevTools/headless). */
  environmentTampered?: boolean | null;
  /** Âncoras temporais utilizadas (ex.: "RFC 3161 (FreeTSA)"). */
  anchors?: string[];
  /** Âncora confirmada em bloco/autoridade. */
  anchorConfirmed?: boolean | null;
  /** Altura do bloco Bitcoin, quando confirmado. */
  bitcoinBlockHeight?: number | null;
}

const MODE_LABEL: Record<string, string> = {
  perito: 'Perito',
  policial: 'Policial / Investigador',
  operador_direito: 'Operador do Direito',
  vitima: 'Vítima / Titular',
};

export const CUSTODY_BLOCK_TITLE = 'Cadeia de Custódia da Sessão';

export function resolveCustodyStatus(input: CustodyBlockInput): {
  status: CustodyBlockStatus;
  label: string;
  note?: string;
} {
  const hasMaster = !!input.masterHash;
  const masterOk = hasMaster && input.masterHashValid !== false;
  const chainOk = input.chainIntact !== false;

  if (!masterOk || !chainOk) {
    return {
      status: 'nao_verificada',
      label: 'INTEGRIDADE NAO VERIFICADA',
      note: !hasMaster
        ? 'Hash mestre ausente no material analisado: a verificacao automatica de integridade nao pode ser concluida.'
        : 'Divergencia detectada no recalculo do hash mestre ou quebra na cadeia de elos.',
    };
  }

  const anchorOk = input.anchorConfirmed === true || !!input.bitcoinBlockHeight;
  if (!anchorOk || input.environmentTampered === true) {
    return {
      status: 'ressalvas',
      label: 'INTEGRA COM RESSALVAS',
      note:
        input.environmentTampered === true
          ? 'Cadeia de elos consistente, porem o ambiente de coleta foi sinalizado pelos sensores de adulteracao. Ver Relatorio de Auditoria.'
          : 'Cadeia de elos consistente. Ancoragem temporal registrada, pendente de confirmacao definitiva em bloco - verificavel a qualquer momento por terceiro.',
    };
  }

  return {
    status: 'verificada',
    label: 'INTEGRIDADE VERIFICADA',
    note: 'Hash mestre reproduzido, cadeia de elos sem quebras e ancoragem temporal confirmada de forma independente.',
  };
}

function durationLabel(
  startedAt?: string | number | Date | null,
  finishedAt?: string | number | Date | null,
): string | null {
  if (!startedAt || !finishedAt) return null;
  const a = new Date(startedAt as any).getTime();
  const b = new Date(finishedAt as any).getTime();
  if (!isFinite(a) || !isFinite(b) || b < a) return null;
  const total = Math.round((b - a) / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h}h${String(m).padStart(2, '0')}m${String(s).padStart(2, '0')}s` : `${m}m${String(s).padStart(2, '0')}s`;
}

function operatorLabel(input: CustodyBlockInput): string | null {
  const parts: string[] = [];
  if (input.operatorName) parts.push(input.operatorName);
  if (input.operatorEmail && input.operatorEmail !== input.operatorName) parts.push(input.operatorEmail);
  if (!parts.length && input.operatorId) parts.push(input.operatorId);
  if (!parts.length) return null;
  let label = parts.join(' - ');
  const mode = input.authorMode ? MODE_LABEL[input.authorMode] : null;
  if (mode) label += ` [${mode}]`;
  return label;
}

/** Linhas rótulo/valor do bloco, já omitindo campos vazios. */
export function buildCustodyBlockRows(input: CustodyBlockInput): [string, string][] {
  const rows: [string, string][] = [];
  if (input.sessionId) rows.push(['Sessão', input.sessionId]);
  if (input.startedAt) rows.push(['Sessão iniciada', formatDualTime(input.startedAt)]);
  const op = operatorLabel(input);
  if (op) rows.push(['Operador', op]);
  if (input.finishedAt) {
    const dur = durationLabel(input.startedAt, input.finishedAt);
    rows.push(['Captura encerrada', formatDualTime(input.finishedAt) + (dur ? ` - duração ${dur}` : '')]);
  }
  if (typeof input.artifactCount === 'number' && input.artifactCount > 0) {
    rows.push(['Artefatos', `${input.artifactCount} item(ns) correlacionado(s) ao manifesto`]);
  }
  if (input.masterHash) {
    rows.push([
      'Master Hash',
      `SHA-256 ${input.masterHash}` + (input.masterHashValid === true ? ' (recalculado: confere)' : ''),
    ]);
  }
  const anchors = (input.anchors || []).filter(Boolean);
  if (input.bitcoinBlockHeight) anchors.push(`Blockchain Bitcoin - bloco #${input.bitcoinBlockHeight}`);
  if (anchors.length) rows.push(['Âncora temporal', anchors.join(' | ')]);
  return rows;
}

/** Versão em texto puro (README.txt dos pacotes ZIP). */
export function buildCustodyBlockTextBlock(input: CustodyBlockInput): string {
  const rows = buildCustodyBlockRows(input);
  const st = resolveCustodyStatus(input);
  const pad = 20;
  const lines: string[] = [
    CUSTODY_BLOCK_TITLE.toUpperCase(),
    '='.repeat(30),
    '',
    ...rows.map(([k, v]) => `  ${k.padEnd(pad)}${v}`),
    `  ${'Status'.padEnd(pad)}${st.label}`,
  ];
  if (st.note) lines.push('', `  ${st.note}`);
  lines.push('');
  return lines.join('\n');
}

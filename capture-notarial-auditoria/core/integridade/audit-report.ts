/**
 * Requisito 6 — Relatório de Auditoria de Integridade (JSON legível),
 * gerado no encerramento da sessão e incluído no pacote ZIP forense.
 */
import type { ArtifactManifest } from './artifact-manifest';
import { utcNow } from './hash';

export interface IntegrityAuditReport {
  schema: 'trace-hub/sealed-integrity-audit';
  schema_version: '1.0';
  generated_at: string;
  session_id: string;
  target_url: string;
  window: { started_at: string; ended_at: string; duration_seconds: number };
  verdict: 'integra' | 'integra_com_ressalvas' | 'comprometida';
  verdict_reason: string;
  checks: Array<{
    id: string;
    label: string;
    status: 'ok' | 'atencao' | 'falha' | 'nao_aplicavel';
    detail: string;
  }>;
  counters: {
    events: number;
    dom_links: number;
    mutations: number;
    artifacts: number;
    tamper_events: number;
    payload_audits: number;
    payload_mismatches: number;
  };
  hashes: {
    event_merkle_root: string | null;
    dom_final_chain_hash: string | null;
    master_hash: string | null;
  };
  environment: {
    user_agent: string;
    viewport: { width: number; height: number };
    timezone_offset_minutes: number;
    tamper_detected: boolean;
    tamper_methods: string[];
  };
  limitations: string[];
}

const LIMITATIONS = [
  'A captura reflete o conteúdo tal como entregue ao navegador do operador no instante registrado; não atesta a autoria nem a veracidade do conteúdo exibido.',
  'Conteúdo dinâmico (personalização por sessão, geolocalização ou A/B testing) pode não ser reproduzível por terceiros em momento posterior.',
  'A cadeia de DOM só é registrada quando o documento é acessível ao contexto de captura; páginas de origem cruzada sem proxy são registradas apenas por eventos e artefatos visuais.',
  'A ancoragem em blockchain comprova a anterioridade temporal do hash mestre, não o conteúdo em si.',
];

export function buildIntegrityAuditReport(manifest: ArtifactManifest): IntegrityAuditReport {
  const started = Date.parse(manifest.started_at);
  const ended = Date.parse(manifest.ended_at);
  const duration = Number.isFinite(started) && Number.isFinite(ended) ? Math.max(0, Math.round((ended - started) / 1000)) : 0;

  const mismatches = manifest.payload_audit.filter((p) => !p.match);
  const checks: IntegrityAuditReport['checks'] = [
    {
      id: 'event_chain',
      label: 'Cadeia de eventos encadeada por hash',
      status: manifest.event_chain.count > 0 ? 'ok' : 'atencao',
      detail:
        manifest.event_chain.count > 0
          ? `${manifest.event_chain.count} evento(s) encadeado(s); raiz Merkle ${manifest.event_chain.merkle_root ?? 'pendente'}.`
          : 'Nenhum evento registrado na sessão.',
    },
    {
      id: 'dom_chain',
      label: 'Hash chain contínua do DOM',
      status: manifest.dom_chain.count > 0 ? 'ok' : 'nao_aplicavel',
      detail:
        manifest.dom_chain.count > 0
          ? `${manifest.dom_chain.count} snapshot(s) normalizado(s); elo final ${manifest.dom_chain.final_chain_hash}.`
          : 'DOM inacessível ao contexto de captura (origem cruzada sem proxy) — integridade sustentada por eventos e artefatos.',
    },
    {
      id: 'mutations',
      label: 'Registro de mutações do DOM',
      status: manifest.dom_chain.count > 0 ? 'ok' : 'nao_aplicavel',
      detail: `${manifest.mutations_count} mutação(ões) observada(s) durante a coleta.`,
    },
    {
      id: 'artifacts',
      label: 'Correlação artefato ↔ estado do DOM',
      status: manifest.artifacts.length > 0 ? 'ok' : 'atencao',
      detail: `${manifest.artifacts.length} artefato(s) com SHA-256 individual e vínculo ao elo do DOM/evento correspondente.`,
    },
    {
      id: 'payload_audit',
      label: 'Auditoria de payload (local × persistido)',
      status: manifest.payload_audit.length === 0 ? 'nao_aplicavel' : mismatches.length === 0 ? 'ok' : 'falha',
      detail:
        manifest.payload_audit.length === 0
          ? 'Nenhuma comparação de payload registrada.'
          : `${manifest.payload_audit.length} comparação(ões); ${mismatches.length} divergência(s).`,
    },
    {
      id: 'environment',
      label: 'Integridade do ambiente de execução',
      status: manifest.tamper.detected ? 'atencao' : 'ok',
      detail: manifest.tamper.detected
        ? `Sinais de inspeção/adulteração do ambiente: ${manifest.tamper.methods.join(', ')}.`
        : 'Nenhum sinal de DevTools aberto ou de sobrescrita de funções nativas durante a coleta.',
    },
    {
      id: 'master_hash',
      label: 'Master Hash do manifesto',
      status: manifest.master_hash ? 'ok' : 'falha',
      detail: manifest.master_hash
        ? `SHA-256 sobre o manifesto canônico: ${manifest.master_hash}.`
        : 'Master Hash ausente — pacote incompleto.',
    },
  ];

  const hasFailure = checks.some((c) => c.status === 'falha');
  const hasWarning = checks.some((c) => c.status === 'atencao');
  const verdict: IntegrityAuditReport['verdict'] = hasFailure
    ? 'comprometida'
    : hasWarning
      ? 'integra_com_ressalvas'
      : 'integra';

  return {
    schema: 'trace-hub/sealed-integrity-audit',
    schema_version: '1.0',
    generated_at: utcNow(),
    session_id: manifest.session_id,
    target_url: manifest.target_url,
    window: { started_at: manifest.started_at, ended_at: manifest.ended_at, duration_seconds: duration },
    verdict,
    verdict_reason: hasFailure
      ? 'Ao menos uma verificação criptográfica falhou — a evidência não deve ser apresentada sem esclarecimento técnico.'
      : hasWarning
        ? 'Todas as verificações criptográficas fecharam, com ressalvas registradas para contra-exame.'
        : 'Todas as verificações criptográficas da sessão fecharam sem divergência.',
    checks,
    counters: {
      events: manifest.event_chain.count,
      dom_links: manifest.dom_chain.count,
      mutations: manifest.mutations_count,
      artifacts: manifest.artifacts.length,
      tamper_events: manifest.tamper.events_count,
      payload_audits: manifest.payload_audit.length,
      payload_mismatches: mismatches.length,
    },
    hashes: {
      event_merkle_root: manifest.event_chain.merkle_root,
      dom_final_chain_hash: manifest.dom_chain.final_chain_hash,
      master_hash: manifest.master_hash ?? null,
    },
    environment: {
      user_agent: manifest.user_agent,
      viewport: manifest.viewport,
      timezone_offset_minutes: manifest.timezone_offset_minutes,
      tamper_detected: manifest.tamper.detected,
      tamper_methods: manifest.tamper.methods,
    },
    limitations: LIMITATIONS,
  };
}

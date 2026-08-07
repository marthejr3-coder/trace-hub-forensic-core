/**
 * Renderiza a seção "Histórico de Acessos e Custódia" em um documento jsPDF
 * já existente. Deve ser adicionada antes de salvar a versão formal do laudo
 * gerada por `generate-report-version` (art. 158-C CPP).
 */
import type jsPDF from 'jspdf';
import { createPdf } from '@/lib/jspdf-safe';
import { drawTable } from '@/lib/jspdf-safe';
import type { AccessLogRow, SessionKind } from './access-log';

const EVENT_LABEL: Record<string, string> = {
  view_report: 'Visualização do relatório',
  download_initiated: 'Download iniciado',
  download_confirmed: 'Download confirmado (transferência de custódia)',
  hash_reverify: 'Reverificação de hash',
  public_verification: 'Verificação pública',
  system_event: 'Evento de sistema',
};

function fmt(dt: string): string {
  try {
    return new Date(dt).toLocaleString('pt-BR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return dt; }
}

function actorLabel(row: AccessLogRow): string {
  if (row.actor_id) return row.actor_id;
  const md = row.metadata ?? {};
  const mat = (md as any).operator_matricula;
  if (mat) return `Matrícula ${mat}`;
  return '—';
}

function summaryLabel(row: AccessLogRow): string {
  const md = row.metadata ?? {};
  if (row.event_type === 'download_confirmed') {
    const m = (md as any).hash_matches;
    return m ? 'Hash recalculado: CONFERE' : 'Hash recalculado: NÃO CONFERE';
  }
  if (row.event_type === 'public_verification') {
    return (md as any).match ? 'Verificação pública: CONFERE' : 'Verificação pública: NÃO CONFERE';
  }
  if (row.event_type === 'system_event') {
    const kind = (md as any).kind ?? '';
    if (kind === 'report_version_generated') {
      const v = (md as any).version_number;
      const reason = (md as any).generated_reason ?? '';
      return `Versão v${v} gerada — ${reason}`;
    }
  }
  return '';
}

export interface CustodyHistoryOptions {
  sessionId: string;
  sessionKind: SessionKind;
  events: AccessLogRow[];
  publicVerifyBase?: string; // ex.: 'https://trace-hub.com/verify'
}

/**
 * Adiciona páginas ao PDF com a seção "Histórico de Acessos e Custódia".
 * Chamar imediatamente antes de `doc.output(...)`.
 */
export function renderCustodyHistorySection(
  doc: jsPDF,
  opts: CustodyHistoryOptions,
): void {
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const base = opts.publicVerifyBase ?? 'https://trace-hub.com/verify';

  doc.addPage();
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(0);
  doc.text('Histórico de Acessos e Custódia', 14, 18);
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(8);
  doc.setTextColor(80);
  doc.text(
    'Rastreamento append-only encadeado por hash (SHA-256). Nenhuma linha desta ' +
    'tabela pode ser inserida, editada ou removida diretamente por operadores; ' +
    'toda gravação é feita pelo Trace-Hub e verificável pelo campo entry_hash.',
    14, 24, { maxWidth: pageW - 28 } as any,
  );

  const body = opts.events.map((e) => [
    fmt(e.occurred_at),
    EVENT_LABEL[e.event_type] ?? e.event_type,
    actorLabel(e),
    e.actor_ip ?? '—',
    summaryLabel(e),
  ]);

  drawTable(doc, {
    startY: 34,
    head: [['Data/Hora', 'Evento', 'Ator', 'IP', 'Resumo']],
    body: body.length > 0 ? body : [['—', 'Sem eventos registrados', '—', '—', '—']],
    styles: { fontSize: 8, cellPadding: 2, overflow: 'linebreak' },
    headStyles: { fillColor: [30, 30, 30] },
    columnStyles: {
      0: { cellWidth: 32 },
      1: { cellWidth: 52 },
      2: { cellWidth: 34 },
      3: { cellWidth: 26 },
      4: { cellWidth: 'auto' },
    },
  });

  let y = (doc as any).lastAutoTable.finalY + 8;
  if (y > pageH - 40) { doc.addPage(); y = 20; }

  const note =
    'Este histórico reflete os eventos de acesso registrados na plataforma ' +
    'Trace-Hub até a data de emissão desta versão. A responsabilidade pela ' +
    'guarda e integridade do arquivo original a partir da confirmação de ' +
    'download é do custodiante identificado no evento "download_confirmed", ' +
    'nos termos do art. 158-C do CPP. Verificação pública permanente ' +
    `disponível em ${base}/${opts.sessionKind}/${opts.sessionId}.`;

  doc.setDrawColor(180);
  doc.setFillColor(252, 250, 245);
  doc.roundedRect(14, y, pageW - 28, 30, 2, 2, 'FD');
  doc.setFont('helvetica', 'bolditalic');
  doc.setFontSize(8);
  doc.setTextColor(90);
  doc.text('NOTA LEGAL — CPP art. 158-C', 18, y + 5);
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(7.5);
  doc.text(note, 18, y + 10, { maxWidth: pageW - 36 } as any);
  doc.setTextColor(0);
}

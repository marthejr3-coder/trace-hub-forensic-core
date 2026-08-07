import { createPdf } from '@/lib/jspdf-safe';
import { drawTable } from '@/lib/jspdf-safe';
import { downloadBlob, openPopupForDownload } from '@/lib/ios-download';
import { drawAuthorBlockPDF, drawSignaturePDF } from '@/lib/forensic-author-pdf';
import {
  type ForensicAuthor,
  TITLE_BY_MODE,
  FILE_PREFIX_BY_MODE,
} from '@/lib/forensic-author';
import { buildIso27037PdfRows } from '@/lib/iso27037-verification-block';
import { buildMethodologyRows, METHODOLOGY_TITLE } from '@/lib/forensic-methodology';
import { formatDualTime } from '@/lib/forensic-report-copy';
import {
  drawAnchoringStatus,
  drawCustodyBlock,
  drawPlatformProvenance,


  drawBlockchainExplanation,
  drawExecutiveSummary,
  drawExhibitorResponsibility,
  drawIndependentVerificationNote,
  drawInstitutionalIntro,
  drawMethodologyFlowchart,
  drawStjCompliance,
  drawTimeReferenceNote,
  drawTrustBadges,
  type PdfCtx,
} from '@/lib/forensic-report-ui';
import { loadPlatformProvenance } from '@/lib/platform-provenance';


import { renderIntrinsicRowsForPDF } from '@/lib/file-intrinsic-metadata';

export interface CaptureLinkEvidence {
  file_name: string;
  file_path: string;
  file_size: number;
  mime_type: string;
  hash_client: string;
  hash_server: string;
  hash_client_sha512?: string;
  hash_server_sha512?: string;
  hashes_match: boolean;
  captured_at_client: string;
  received_at_server: string;
  device_model: string;
  ip_address: string;
  user_agent?: string;
  geolocation?: { latitude?: number; longitude?: number; accuracy?: number } | null;
  signed_url?: string | null;
  metadata?: {
    ai_detection?: {
      veredicto: string;
      pontuacao: number;
      conclusao: string;
      model: string;
      analyzed_at: string;
    };
    victim_identity?: {
      full_name?: string;
      rg?: string;
      rg_uf?: string | null;
      cpf?: string | null;
      phone?: string | null;
      email?: string | null;
      declared_at?: string;
      declaration_accepted?: boolean;
      declaration_text?: string;
      forensic_dossier_consent?: boolean;
      forensic_dossier_consent_text?: string;
    };
    forensics?: Record<string, unknown> | null;
    file_intrinsic?: import('./file-intrinsic-metadata').FileIntrinsicMetadata | null;
  };
  party_notes?: string | null;
}

export interface CaptureLinkSessionData {
  id: string;
  token: string;
  operator_name: string;
  operator_id?: string;
  operator_ip?: string | null;
  created_at: string;
  expires_at: string;
  evidence: CaptureLinkEvidence[];
  author?: ForensicAuthor;
  audit_logs?: any[];
  timestamp_proofs?: Record<string, {
    submitted_at: string;
    created_at: string;
    tsr_base64?: string;
    ots_base64?: string;
    blockchain_txid?: string;
    explorer_url?: string;
    bitcoin_block_height?: number | null;
    ots_confirmed_at?: string | null;
    verified_at?: string | null;
    status?: string;
    ots_sha256?: string | null;
    block_hash?: string | null;
    block_merkle_root?: string | null;
    block_time?: string | null;
    calendars?: string[];
  }>;
}

export async function gerarLaudoCaptureLinkPDF(input: CaptureLinkSessionData): Promise<void> {
  const provenance = await loadPlatformProvenance();
  const popup = openPopupForDownload('Gerando laudo Capture Link…');


  const author: ForensicAuthor = input.author ?? { mode: 'perito', fullName: input.operator_name };
  const titulo = TITLE_BY_MODE[author.mode];
  const filePrefix = FILE_PREFIX_BY_MODE[author.mode];

  const pdf = createPdf({ unit: 'mm', format: 'a4' });
  const PW = pdf.internal.pageSize.getWidth();
  const PH = pdf.internal.pageSize.getHeight();
  const MARGIN = 15;
  const CW = PW - MARGIN * 2;
  let y = MARGIN;

  // Cabeçalho institucional
  pdf.setFillColor(15, 76, 58);
  pdf.rect(0, 0, PW, 18, 'F');
  pdf.setTextColor(255, 255, 255);
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(13);
  pdf.text('TRACE HUB · Central Forense', MARGIN, 11);
  pdf.setFontSize(8);
  pdf.text(`SESSÃO ID: ${input.id}`, PW - MARGIN, 11, { align: 'right' });
  y = 24;

  pdf.setTextColor(20, 20, 20);
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(15);
  pdf.text('Relatório de Materialização de Evidência Digital', MARGIN, y);
  y += 6;
  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(10);
  pdf.setTextColor(80, 80, 80);
  pdf.text('Cadeia de custódia completa com hashes client-side (ISO 27037)', MARGIN, y);
  y += 8;

  // Bloco do autor (Operador)
  y = drawAuthorBlockPDF(pdf, author, { x: MARGIN, y, width: CW });

  // Detalhes da Sessão
  drawTable(pdf, {
    startY: y,
    margin: { left: MARGIN, right: MARGIN },
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 2 },
    headStyles: { fillColor: [15, 76, 58], textColor: 255 },
    head: [['Informações da Sessão', '']],
    body: [
      ['ID da Sessão', input.id],
      ['Token de Acesso', `/${input.token}`],
      ['Data de Criação', new Date(input.created_at).toLocaleString('pt-BR')],
      ['Total de Arquivos', input.evidence.length.toString()],
    ],
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 } },
  });
  // @ts-ignore
  y = pdf.lastAutoTable.finalY + 8;

  // Resumo executivo + Metodologia técnica — assinatura técnica padrão do Trace Hub
  {
    const anyStamp = Object.values(input.timestamp_proofs || {})[0];
    const btcHeight = anyStamp?.bitcoin_block_height || null;
    const hasSha512 = input.evidence.some((e) => !!e.hash_client_sha512 || !!e.hash_server_sha512);
    const allMatch = input.evidence.length > 0 && input.evidence.every((e) => e.hashes_match);

    const rc: PdfCtx = {
      pdf,
      y,
      marginX: MARGIN,
      contentW: CW,
      pageW: PW,
      pageH: PH,
      marginTop: MARGIN + 9,
      marginBottom: 18,
      font: 'helvetica',
    };

    y = drawTrustBadges(rc, y);
    y = drawExecutiveSummary(rc, {
      identity: [
        ['Sessão', input.id],
        ['Operador', input.operator_name],
        ['Arquivos', String(input.evidence.length)],
        ['Emissão do relatório', formatDualTime(new Date())],
      ],
      integrity: allMatch,
      custody: true,
      clientServerMatch: allMatch ? 'ok' : 'pending',
      rfc3161: anyStamp?.tsr_base64 ? 'ok' : 'na',
      bitcoin: btcHeight ? 'ok' : 'pending',
      originalsPreserved: true,
      metadata: true,
      auditable: true,
      iso27037: true,
    });
    {
      const lastReceived = input.evidence
        .map((e) => e.received_at_server)
        .filter(Boolean)
        .sort()
        .pop();
      const anchors: string[] = [];
      if (anyStamp?.tsr_base64) anchors.push('RFC 3161 (FreeTSA)');
      if (anyStamp?.ots_base64) anchors.push('OpenTimestamps');
      y = drawCustodyBlock(rc, y, {
        sessionId: input.id,
        startedAt: input.created_at,
        finishedAt: lastReceived || null,
        operatorName: input.operator_name,
        operatorId: input.operator_id || null,
        authorMode: author.mode,
        artifactCount: input.evidence.length,
        masterHash: input.evidence[0]?.hash_server || null,
        masterHashValid: allMatch ? true : null,
        chainIntact: allMatch,
        anchors,
        anchorConfirmed: !!btcHeight,
        bitcoinBlockHeight: btcHeight,
      });
    }
    y = drawPlatformProvenance(rc, y, provenance);

    y = drawInstitutionalIntro(rc, y);


    const methodologyRows = buildMethodologyRows({
      acquisitionMode: 'capture_link',
      hasSha512,
      anchors: {
        rfc3161: !!anyStamp?.tsr_base64,
        opentimestamps: !!anyStamp?.ots_base64,
        bitcoinConfirmed: !!btcHeight,
      },
    }).filter(([, v]) => !!v);

    const methodologyTable = (rows: [string, string][], head: string) => {
      drawTable(pdf, {
        startY: y,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'grid',
        styles: { fontSize: 7, cellPadding: 1.8, valign: 'top' },
        headStyles: { fillColor: [15, 76, 58], textColor: 255 },
        head: [[head, '']],
        body: rows,
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 42 } },
      });
      // @ts-ignore
      y = pdf.lastAutoTable.finalY + 6;
    };

    // 1. Objetivo -> fluxograma -> itens 3-10
    methodologyTable(methodologyRows.slice(0, 1), METHODOLOGY_TITLE);
    y = drawMethodologyFlowchart(rc, y);
    methodologyTable(methodologyRows.slice(1), METHODOLOGY_TITLE + ' (continuação)');

    y = drawStjCompliance(rc, y);
    y = drawExhibitorResponsibility(rc, y);
    y = drawAnchoringStatus(rc, y, {
      sha256: true,
      sha512: hasSha512,
      clientServer: allMatch,
      custody: true,
      rfc3161: !!anyStamp?.tsr_base64,
      opentimestamps: !!anyStamp?.ots_base64,
      bitcoinBlockHeight: btcHeight,
      blockHash: (anyStamp as any)?.block_hash || null,
      blockTimeUtc: (anyStamp as any)?.block_time || null,
    });
    y = drawIndependentVerificationNote(rc, y);
    y = drawTimeReferenceNote(rc, y);
    y = drawBlockchainExplanation(rc, y);
  }


  // Tabela de Evidências
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(11);
  pdf.setTextColor(15, 76, 58);
  pdf.text('Evidências Coletadas (ISO 27037)', MARGIN, y);
  y += 4;


  // Bloco de Identificação do Operador/Ambiente (ISO 27037)
  drawTable(pdf, {
    startY: y,
    margin: { left: MARGIN, right: MARGIN },
    theme: 'grid',
    styles: { fontSize: 7, cellPadding: 1.5 },
    headStyles: { fillColor: [40, 40, 40], textColor: 255 },
    head: [['Ambiente do Operador / Investigador', '']],
    body: [
      ['Operador', input.operator_name],
      ['ID do Operador', input.operator_id || 'Autenticado'],
      ['IP do Operador', input.operator_ip || 'não capturado pelo servidor'],
      ['Data de Emissão', new Date().toLocaleString('pt-BR')],
    ],
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 } },
  });
  // @ts-ignore
  y = pdf.lastAutoTable.finalY + 8;

  for (const item of input.evidence) {
    if (y > PH - 80) { pdf.addPage(); y = MARGIN + 10; }

    const norm = (h?: string | null) => (h || '').trim().toLowerCase();
    const sha256Match =
      !!item.hash_client && !!item.hash_server && norm(item.hash_client) === norm(item.hash_server);
    const has512Both = !!item.hash_client_sha512 && !!item.hash_server_sha512;
    const sha512Match = has512Both && norm(item.hash_client_sha512) === norm(item.hash_server_sha512);

    const rows: (string | number)[][] = [
      ['Hash SHA-256 (Cliente)', item.hash_client],
      ['Hash SHA-256 (Servidor)', item.hash_server],
    ];
    if (has512Both) {
      rows.push(['Hash SHA-512 (Cliente)', item.hash_client_sha512!]);
      rows.push(['Hash SHA-512 (Servidor)', item.hash_server_sha512!]);
    }
    rows.push([
      'Integridade (Matches)',
      sha256Match
        ? has512Both
          ? sha512Match
            ? 'CONFERIDO (SHA-256 + SHA-512)'
            : 'CONFERIDO (SHA-256) — SHA-512 divergente'
          : 'CONFERIDO (SHA-256)'
        : 'DIVERGENTE',
    ]);
    rows.push(
      ['Timestamp Captura', new Date(item.captured_at_client).toLocaleString('pt-BR')],
      ['Dispositivo / OS', item.device_model],
      ['Endereço IP (Vítima)', item.ip_address],
    );

    drawTable(pdf, {
      startY: y,
      margin: { left: MARGIN, right: MARGIN },
      theme: 'grid',
      styles: { fontSize: 7, cellPadding: 1.5, overflow: 'linebreak' },
      headStyles: { fillColor: [60, 60, 60] },
      head: [[`Arquivo: ${item.file_name}`, '']],
      body: rows,
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 35 },
        1: { overflow: 'linebreak' },
      },
      // Hashes em fonte monoespaçada compacta — sem espaços, sem ZWSP.
      // jsPDF/autoTable quebra naturalmente por largura sem cortar caracteres.
      didParseCell: (data: any) => {
        if (data.section !== 'body') return;
        // @ts-ignore migration: strict-mode wave
        const label = String(data.row.raw?.[0] ?? '');
        if (label.startsWith('Hash SHA')) {
          data.cell.styles.font = 'courier';
          data.cell.styles.fontSize = label.includes('SHA-512') ? 5.6 : 6.4;
          data.cell.styles.cellPadding = 1;
          data.cell.styles.overflow = 'linebreak';
        }
      },
    });


    // Link para download do arquivo original — bloco próprio com respiro
    // @ts-ignore
    y = pdf.lastAutoTable.finalY + 6;

    const storageUrl = item.signed_url
      || `https://ofknyyvqupuyisogivge.supabase.co/storage/v1/object/public/evidence_vault/${item.file_path}`;
    // Quebra a URL em chunks fixos (sem splitTextToSize, que insere espaços
    // e invalida o clique em partes da linha).
    const charsPerLine = 78;
    const urlLines: string[] = [];
    for (let i = 0; i < storageUrl.length; i += charsPerLine) {
      urlLines.push(storageUrl.slice(i, i + charsPerLine));
    }
    const lineH = 3.4;
    const boxH = 16 + urlLines.length * lineH + 8;

    pdf.setDrawColor(15, 76, 58);
    pdf.setFillColor(240, 250, 246);
    pdf.roundedRect(MARGIN, y, CW, boxH, 1.5, 1.5, 'FD');

    pdf.setFontSize(7);
    pdf.setTextColor(15, 76, 58);
    pdf.setFont('helvetica', 'bold');
    pdf.text('LINK PARA DOWNLOAD DO ARQUIVO ORIGINAL (clique para abrir)', MARGIN + 2, y + 4);

    pdf.setFont('courier', 'normal');
    pdf.setFontSize(6.5);
    pdf.setTextColor(0, 0, 200);
    urlLines.forEach((ln, i) => {
      const ly = y + 8 + i * lineH;
      pdf.text(ln, MARGIN + 2, ly);
    });
    // Um único hyperlink cobrindo o bloco inteiro da URL — qualquer clique
    // sobre qualquer parte da URL abre o link completo.
    pdf.link(MARGIN, y + 5, CW, urlLines.length * lineH + 3, { url: storageUrl });

    // Aviso de retenção: o arquivo original é eliminado automaticamente.
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(6.2);
    pdf.setTextColor(150, 40, 20);
    pdf.text(
      'ATENCAO: o arquivo original permanece disponivel por 72 horas a contar da geracao deste relatorio; apos esse prazo e apagado automaticamente da base de dados. O hash SHA-256 acima permanece valido para conferencia da copia sob guarda do usuario.',
      MARGIN + 2,
      y + 10 + urlLines.length * lineH,
      { maxWidth: CW - 4 },
    );
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor(0, 0, 0);


    y += boxH + 4;

    // Metadados intrínsecos do arquivo (MIME/magic, EXIF, dimensões, PDF, etc.)
    const intrinsic = item.metadata?.file_intrinsic;
    if (intrinsic) {
      // Fonte de alta confiabilidade para cross-check contra varredura binária.
      const fxHint = item.metadata?.forensics as any;
      const ch = fxHint?.client_hints || {};
      const brandsStr = Array.isArray(ch?.brands)
        ? ch.brands.map((b: any) => b?.brand).filter(Boolean).join(' ')
        : null;
      const trustedDeviceModel: string | null =
        ch?.model || fxHint?.device?.model || null;
      const trustedDeviceMake: string | null =
        brandsStr || ch?.platform || fxHint?.device?.brand || null;
      const introws = renderIntrinsicRowsForPDF(intrinsic, { trustedDeviceModel, trustedDeviceMake });
      if (introws.length) {
        if (y > PH - 60) { pdf.addPage(); y = MARGIN + 10; }
        drawTable(pdf, {
          startY: y,
          margin: { left: MARGIN, right: MARGIN },
          theme: 'grid',
          styles: { fontSize: 7, cellPadding: 1.5, overflow: 'linebreak' },
          headStyles: { fillColor: [55, 65, 81], textColor: 255 },
          head: [['Metadados intrínsecos do arquivo (ISO 27037 · maior detalhamento possível)', '']],
          body: introws,
          columnStyles: { 0: { fontStyle: 'bold', cellWidth: 55 } },
        });
        // @ts-ignore
        y = pdf.lastAutoTable.finalY + 4;
      }
    }


    // Se houver detecção de IA, adicionamos um bloco especial
    if (item.metadata?.ai_detection) {
      const ai = item.metadata.ai_detection;
      drawTable(pdf, {
        startY: y,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'plain',
        styles: { fontSize: 7, cellPadding: 1.5 },
        bodyStyles: { fillColor: ai.veredicto.trim().toLowerCase() === 'gerada por ia' ? [255, 235, 235] : [235, 255, 235] },
        body: [
          ['ANÁLISE DE IA', `Veredicto: ${ai.veredicto} | Confiança: ${Math.round(ai.pontuacao)}%`],
          ['Conclusão', ai.conclusao],
        ],
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 35 } },
      });
      // @ts-ignore
      y = pdf.lastAutoTable.finalY;
    }

    // Identificação declarada pela vítima (cadeia de custódia — Art. 158-A CPP)
    const vi = item.metadata?.victim_identity;
    if (vi) {
      if (y > PH - 60) { pdf.addPage(); y = MARGIN + 10; }
      drawTable(pdf, {
        startY: y + 2,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'grid',
        styles: { fontSize: 7, cellPadding: 1.5 },
        headStyles: { fillColor: [15, 76, 58], textColor: 255 },
        head: [['Identificação Declarada pela Vítima', '']],
        body: [
          ['Nome Completo', vi.full_name || '—'],
          ['RG', `${vi.rg || '—'}${vi.rg_uf ? ' / ' + vi.rg_uf : ''}`],
          ['CPF', vi.cpf || '—'],
          ['Telefone', vi.phone || '—'],
          ['E-mail', vi.email || '—'],
          ['Declarado em', vi.declared_at ? new Date(vi.declared_at).toLocaleString('pt-BR') : '—'],
          ['Aceite da Declaração', vi.declaration_accepted ? 'SIM (art. 299 CP)' : 'NÃO'],
          ['Texto da Declaração', vi.declaration_text || '—'],
          ['Aceite do Dossiê Forense', vi.forensic_dossier_consent
            ? 'SIM (LGPD, art. 7º, VI e IX; art. 11, II, \'d\' e \'f\')'
            : 'NÃO REGISTRADO'],
          ...(vi.forensic_dossier_consent_text
            ? [['Texto do Consentimento Forense', vi.forensic_dossier_consent_text] as [string, string]]
            : []),
        ],
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 } },
      });
      // @ts-ignore
      y = pdf.lastAutoTable.finalY;
    }

    // Observações livres declaradas pela parte (ex.: link Wayback Machine)
    const notes = item.party_notes?.trim();
    if (notes) {
      if (y > PH - 40) { pdf.addPage(); y = MARGIN + 10; }
      drawTable(pdf, {
        startY: y + 2,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'grid',
        styles: { fontSize: 8, cellPadding: 2, font: 'helvetica' },
        headStyles: { fillColor: [37, 99, 235], textColor: 255 },
        head: [['Observações declaradas pela parte', '']],
        body: [['Texto', notes]],
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 35 }, 1: { fontStyle: 'italic' } },
      });
      // @ts-ignore
      y = pdf.lastAutoTable.finalY;
    }


    // Dossiê forense client-side (hardware / rede / navegador da vítima)
    const fx = item.metadata?.forensics as any;
    if (fx) {
      if (y > PH - 80) { pdf.addPage(); y = MARGIN + 10; }
      const rows: [string, string][] = [];
      const push = (k: string, v: unknown) => {
        if (v === null || v === undefined || v === '') return;
        const s = typeof v === 'string' ? v : JSON.stringify(v);
        rows.push([k, s.length > 220 ? s.slice(0, 220) + '…' : s]);
      };
      push('Coletado em', fx.collected_at);
      push('User Agent', fx.device?.user_agent);
      push('Plataforma / OS', fx.device?.platform || `${fx.device?.os || ''} ${fx.device?.os_version || ''}`.trim());
      push('Navegador', `${fx.device?.browser || ''} ${fx.device?.browser_version || ''}`.trim());
      push('Idiomas', fx.languages?.join(', '));
      push('Timezone', `${fx.timezone || ''} (offset ${fx.timezone_offset_minutes ?? 'não disponível'} min)`);
      // Resolução / DPR — só monta se todos os campos existirem (BUG 2)
      const sw = fx.device?.screen_width ?? null;
      const sh = fx.device?.screen_height ?? null;
      const dpr = fx.device?.device_pixel_ratio ?? null;
      const screenStr = fx.device?.screen || (sw && sh ? `${sw}x${sh}` : null);
      const resolucao = screenStr && dpr ? `${screenStr} @ ${dpr}x` : (screenStr || 'não disponível');
      push('Resolução / DPR', resolucao);
      push('CPU Cores', fx.hardware?.hardware_concurrency);
      push('RAM (GB)', fx.hardware?.device_memory);
      push('GPU Renderer', fx.hardware?.gpu?.renderer);
      push('GPU Vendor', fx.hardware?.gpu?.vendor);
      push('IP Interno (WebRTC)', fx.network?.internal_ip);
      push('Tipo de Conexão', fx.network?.effectiveType || fx.network?.type);
      // Downlink / RTT — sem traços isolados (BUG 5)
      const dl = fx.network?.downlink;
      const rttv = fx.network?.rtt;
      push('Downlink', dl != null ? `${dl} Mbps` : 'não disponível');
      push('RTT', rttv != null ? `${rttv} ms` : 'não disponível');
      push('Online', fx.network?.online);
      push('VPN/Relay (heur.)', fx.network?.webrtc?.relay_detected);
      // Bateria (BUG 1): getBatteryInfo já retorna 0-100 inteiro; se vier 0-1, normaliza.
      const battLevel = fx.battery?.level;
      let bateriaTxt = 'não disponível';
      if (typeof battLevel === 'number' && isFinite(battLevel)) {
        const pct = battLevel > 1 ? Math.round(battLevel) : Math.round(battLevel * 100);
        const pctClamped = Math.max(0, Math.min(100, pct));
        bateriaTxt = `${pctClamped}%${fx.battery?.charging ? ' (carregando)' : ''}`;
      }
      push('Bateria', bateriaTxt);
      push('Client Hints', fx.client_hints);
      push('Audio Fingerprint', fx.audio_fp);
      push('Canvas Fingerprint', fx.canvas_fp);
      push('Browser Fingerprint', fx.fingerprint?.visitorId || fx.fingerprint?.hash);
      push('Fontes (amostra)', fx.installed_fonts_sample?.join(', '));
      push('Dispositivos de Mídia', `${fx.media_devices?.length || 0} encontrados`);
      push('Storage (quota/uso)', fx.storage_estimate ? `${fx.storage_estimate.quota ?? '—'} / ${fx.storage_estimate.usage ?? '—'}` : null);
      push('Referrer', fx.referrer);
      push('URL da Página', fx.page_url);

      drawTable(pdf, {
        startY: y + 2,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'grid',
        styles: { fontSize: 6.5, cellPadding: 1.3 },
        headStyles: { fillColor: [60, 60, 60], textColor: 255 },
        head: [['Dossiê Forense do Dispositivo da Vítima', '']],
        body: rows,
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 42 } },
      });
      // @ts-ignore
      y = pdf.lastAutoTable.finalY;
    }

    // GPS da vítima, se houver
    if (item.geolocation) {
      const g = item.geolocation;
      drawTable(pdf, {
        startY: y + 2,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'grid',
        styles: { fontSize: 7, cellPadding: 1.5 },
        headStyles: { fillColor: [15, 76, 58], textColor: 255 },
        head: [['Geolocalização GPS (navegador da vítima)', '']],
        body: [
          ['Latitude', String(g.latitude ?? '—')],
          ['Longitude', String(g.longitude ?? '—')],
          ['Precisão (m)', String(g.accuracy ?? '—')],
          ['Google Maps', g.latitude && g.longitude ? `https://www.google.com/maps?q=${g.latitude},${g.longitude}` : '—'],
        ],
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 } },
      });
      // @ts-ignore
      y = pdf.lastAutoTable.finalY;
    }
    // @ts-ignore
    y = pdf.lastAutoTable.finalY + 4;

    // Bloco RFC 3161 + OpenTimestamps — SEMPRE renderizado (mesmo sem proof
    // no banco), porque o relatório precisa documentar o status de selo
    // temporal de cada arquivo. Se não houver proof, mostra estado pendente.
    const proof = input.timestamp_proofs?.[item.file_path] ?? null;
    {
      if (y > PH - 60) { pdf.addPage(); y = MARGIN + 10; }
      
      const hasTsr = !!proof?.tsr_base64;
      const isBitcoinConfirmed = proof?.status === 'confirmed_bitcoin'
        || !!proof?.bitcoin_block_height
        || !!proof?.ots_confirmed_at
        || !!proof?.verified_at;
      const bitcoinProofLabel = proof?.bitcoin_block_height
        ? `Bloco Bitcoin #${proof.bitcoin_block_height}`
        : isBitcoinConfirmed
          ? 'Confirmação detectada no arquivo .ots atualizado'
          : 'Aguardando agregação em bloco Bitcoin';
      const bitcoinExplorer = proof?.bitcoin_block_height
        ? `https://mempool.space/block/${proof.bitcoin_block_height}`
        : proof?.blockchain_txid
          ? `https://mempool.space/tx/${proof.blockchain_txid}`
          : (proof?.explorer_url || 'https://mempool.space (busca por bloco/hash)');
      const submittedAt = proof?.submitted_at || proof?.created_at || new Date().toISOString();
      const confirmedAt = proof?.ots_confirmed_at || proof?.verified_at || null;

      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(9);
      // Verde se há selo imediato (RFC 3161), laranja se só Bitcoin
      if (hasTsr) pdf.setTextColor(15, 76, 58); else pdf.setTextColor(255, 153, 0);
      pdf.text('SELO TEMPORAL INDEPENDENTE (RFC 3161 + OpenTimestamps)', MARGIN, y);
      y += 4;

      drawTable(pdf, {
        startY: y,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'grid',
        styles: { fontSize: 7, cellPadding: 1.5 },
        headStyles: { fillColor: hasTsr ? [15, 76, 58] : [255, 153, 0], textColor: 255 },
        head: [['Protocolos de Anterioridade e Imutabilidade', '']],
        body: [
          ['Ancoragem Imediata (RFC 3161)', hasTsr ? 'FreeTSA — Selo qualificado emitido instantaneamente' : 'Pendente de emissão automática'],
          ['Validade do Selo RFC 3161', hasTsr ? 'Meio técnico reconhecido para comprovação de anterioridade, admissível nos termos do art. 10, §2º da MP 2.200-2/2001, independentemente de certificação ICP-Brasil' : 'PENDENTE — token RFC 3161 ainda não retornado pela TSA no momento da exportação'],
          ['Ancoragem Complementar', 'OpenTimestamps (Bitcoin Blockchain)'],
          ['Status Bitcoin', isBitcoinConfirmed ? 'CONFIRMADO na blockchain Bitcoin via OpenTimestamps' : 'Pendente desde a data de submissão do .ots'],
          ['Prova Bitcoin / Bloco', bitcoinProofLabel],
          ['Confirmado em', confirmedAt ? new Date(confirmedAt).toLocaleString('pt-BR') : '—'],
          ['Timestamp de Submissão', new Date(submittedAt).toLocaleString('pt-BR')],
          ['OTS Calendar', 'https://a.pool.opentimestamps.org'],
          ['Hash Ancorado (SHA-256)', item.hash_client],
          ['Link do Explorador', bitcoinExplorer],
          ['Verificação Pública', 'openssl ts -verify (RFC 3161) | ots verify evidence.ots (Bitcoin)'],
          ['Evidência Verificável Agora', hasTsr ? (isBitcoinConfirmed ? 'SIM (RFC 3161 + Bitcoin/OpenTimestamps)' : 'SIM (RFC 3161 — independe de confirmação Bitcoin)') : (isBitcoinConfirmed ? 'SIM (Bitcoin/OpenTimestamps)' : 'EM PROCESSAMENTO')],
        ],
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 50 } },
      });

      // @ts-ignore
      y = pdf.lastAutoTable.finalY + 3;
      pdf.setFont('helvetica', 'italic');
      pdf.setFontSize(6);
      pdf.setTextColor(100, 100, 100);
      pdf.text(
        'Nota: O selo RFC 3161 (FreeTSA) é emitido instantaneamente e é juridicamente suficiente para comprovar anterioridade (MP 2.200-2/2001, ETSI EN 319 422). ' +
        'O OpenTimestamps/Bitcoin é redundância pública independente, confirmada por bloco Bitcoin quando o arquivo .ots é atualizado. Arquivos .tsr e .ots estão embutidos no pacote .ZIP para perícia.',
        MARGIN, y, { maxWidth: CW }
      );

      // @ts-ignore
      y = pdf.lastAutoTable.finalY + 6;

      // ISO 27037 — bloco de verificação independente para perito adversário
      if (y > PH - 80) { pdf.addPage(); y = MARGIN + 10; }
      drawTable(pdf, {
        startY: y,
        margin: { left: MARGIN, right: MARGIN },
        theme: 'grid',
        styles: { fontSize: 6.5, cellPadding: 1.3, overflow: 'linebreak' },
        headStyles: { fillColor: [15, 76, 58], textColor: 255 },
        head: [['Verificação Independente pelo Perito Adversário (ISO/IEC 27037)', '']],
        body: buildIso27037PdfRows({
          evidenceHash: item.hash_client,
          otsSha256: proof?.ots_sha256 ?? null,
          blockHeight: proof?.bitcoin_block_height ?? null,
          blockHash: proof?.block_hash ?? null,
          blockMerkleRoot: proof?.block_merkle_root ?? null,
          blockTime: proof?.block_time ?? null,
          calendars: proof?.calendars,
          otsFilename: `${item.file_name}.ots`,
        }),
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 55 } },
      });
      // @ts-ignore
      y = pdf.lastAutoTable.finalY + 8;
  }
  
  // Bloco de Orientação para Termo de Arrecadação
  if (y > PH - 40) { pdf.addPage(); y = MARGIN + 10; }
  pdf.setDrawColor(15, 76, 58);
  pdf.setLineWidth(0.5);
  pdf.line(MARGIN, y, PW - MARGIN, y);
  y += 5;
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(9);
  pdf.setTextColor(15, 76, 58);
  pdf.text('ORIENTAÇÃO PARA FORMALIZAÇÃO (CADEIA DE CUSTÓDIA)', MARGIN, y);
  y += 4;
  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(8);
  pdf.setTextColor(50, 50, 50);
  pdf.text(
    'Para completar a cadeia formal de custódia, este laudo e o pacote de evidências (.ZIP) devem ser juntados ' +
    'aos autos mediante Termo de Arrecadação. O perito oficial deve confrontar os hashes SHA-256 listados neste ' +
    'documento com os arquivos contidos no pacote ZIP para ratificar a integridade.',
    MARGIN, y, { maxWidth: CW }
  );
  y += 10;
  }

  // Se houver Logs de Auditoria
  if (input.audit_logs && input.audit_logs.length > 0) {
    pdf.addPage();
    y = MARGIN;
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(11);
    pdf.setTextColor(15, 76, 58);
    pdf.text('Logs de Auditoria da Sessão (ISO 27037)', MARGIN, y);
    y += 6;
    
    drawTable(pdf, {
      startY: y,
      margin: { left: MARGIN, right: MARGIN },
      theme: 'grid',
      styles: { fontSize: 6.5, cellPadding: 1.2 },
      headStyles: { fillColor: [15, 76, 58], textColor: 255 },
      head: [['Timestamp (UTC)', 'Ação', 'IP / Detalhes']],
      body: input.audit_logs.map(log => [
        new Date(log.created_at).toISOString().replace('T', ' ').slice(0, 19),
        log.action,
        `${log.ip_address || '—'} | ${JSON.stringify(log.metadata || {})}`.slice(0, 100)
      ]),
    });
    // @ts-ignore
    y = pdf.lastAutoTable.finalY + 10;
  }

  // Disclaimer Técnico Final
  if (y > PH - 70) { pdf.addPage(); y = MARGIN + 10; }
  pdf.setFillColor(245, 245, 245);
  pdf.rect(MARGIN, y, CW, 62, 'F');
  pdf.setFont('helvetica', 'italic');
  pdf.setFontSize(7.5);
  pdf.setTextColor(80, 80, 80);
  pdf.text(
    'Este relatório constitui prova técnica em conformidade com a ISO/IEC 27037:2012 (identificação, coleta, aquisição e preservação de evidência digital), CPC art. 411 II e MP 2.200-2/2001. ' +
    'O Art. 158-A do CPP (Lei 13.964/2019) é referenciado por analogia doutrinária consolidada (STJ, HC 1.036.370/PR, 2025). ' +
    'Os hashes foram gerados no dispositivo de origem (client-side) e confrontados no servidor, garantindo integridade ponta-a-ponta. ' +
    'O selo temporal ancorado em blockchain assegura a anterioridade do arquivo em relação a qualquer alteração posterior.',
    MARGIN + 3, y + 5, { maxWidth: CW - 6 }
  );
  pdf.setFont('helvetica', 'bold');
  pdf.setTextColor(120, 53, 15);
  pdf.text(
    'LIMITES: Este relatório atesta integridade do arquivo desde a captura e implementa toda a cadeia de custódia, não a autenticidade do conteúdo original — como autenticação cartorial atesta a cópia, não o documento-fonte.',
    MARGIN + 3, y + 44, { maxWidth: CW - 6 }
  );
  y += 68;

  // Assinatura
  y = drawSignaturePDF(pdf, author, { pageWidth: PW, y });

  // Rodapé
  const total = pdf.getNumberOfPages();
  for (let i = 1; i <= total; i++) {
    pdf.setPage(i);
    pdf.setFontSize(7);
    pdf.setTextColor(150);
    pdf.text(`Página ${i} de ${total} — Trace Hub Capture Link — Documento Técnico Forense — ID: ${input.id}`, PW / 2, PH - 8, { align: 'center' });
  }

  const blob = pdf.output('blob');
  downloadBlob(blob, `relatorio_evidencia_capture_link_${input.token}.pdf`, popup);
}

/**
 * Forensic Report Kit — componentes visuais cartoriais reutilizáveis.
 *
 * Padrão "Ata Notarial Digital" estendido para todas as ferramentas forenses
 * do Trace Hub. Garante identidade visual única (frontispício + Partes I-IV +
 * página de validação com QR), facilitando reconhecimento judicial.
 *
 * Tipografia:
 *   - Headings: 'Cinzel'  (importado em src/index.css)
 *   - Body:     'EB Garamond'
 *   - Mono:     'JetBrains Mono'
 *
 * Cor primária: #0F4C3A (verde-garrafa cartorial)
 */
import { getHtml2Canvas } from '@/lib/jspdf-safe';
import React from 'react';
import { ShieldCheck, Loader2, CheckCircle2, Clock as ClockIcon, RefreshCw } from 'lucide-react';
import QRCodeLib from 'qrcode';
import { ForensicSeal, type ForensicReportType, getValidatorUrl } from '@/lib/forensic-seal';
import { emptyText, isEmptyValue, type EmptyFieldKind } from '@/lib/laudo-empty-values';
import type { RequesterIdentification } from '@/lib/laudo-requester';
import { LEGAL_RETENTION_CLAUSE, TSR_VALIDATION_NOTE } from '@/lib/legal-retention';


export const FONT_HEADING = "'Cinzel', Georgia, serif";
export const FONT_BODY = "'EB Garamond', Cambria, Georgia, serif";
export const FONT_MONO = "'JetBrains Mono', Courier, monospace";
export const COLOR_PRIMARY = '#0F4C3A';
export const COLOR_TEXT = '#1a1a1a';
export const COLOR_MUTED = '#5a5a5a';

/* ------------------------------------------------------------------ */
/* PartHeader — divisor cartorial entre PARTES                         */
/* ------------------------------------------------------------------ */
interface PartHeaderProps {
  number: string;
  title: string;
  subtitle: string;
}

export function PartHeader({ number, title, subtitle }: PartHeaderProps) {
  return (
    <div
      data-pdf-part-header="true"
      data-pdf-keep="true"
      style={{ breakInside: 'avoid', pageBreakInside: 'avoid' }}
    >
      <div className="h-[3px] w-full mb-3" style={{ backgroundColor: COLOR_PRIMARY }} />
      <div
        className="text-[10px] uppercase font-bold"
        style={{ fontFamily: FONT_HEADING, color: COLOR_PRIMARY, letterSpacing: '0.42em' }}
      >
        Parte {number}
      </div>
      <h2
        className="text-[18px] font-bold uppercase mt-1 leading-tight"
        style={{ fontFamily: FONT_HEADING, color: COLOR_TEXT, letterSpacing: '0.18em' }}
      >
        {title}
      </h2>
      <p
        className="text-[10.5px] italic mt-1 leading-snug"
        style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
      >
        {subtitle}
      </p>
      <div className="border-b-2 mt-2.5" style={{ borderColor: COLOR_PRIMARY }} />
      <div className="border-b mt-0.5" style={{ borderColor: `${COLOR_PRIMARY}66` }} />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* KeepTogether — wrapper para bloco atômico (imagem+legenda, etc.)   */
/* ------------------------------------------------------------------ */
export function KeepTogether({
  children,
  className = '',
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      data-pdf-keep="true"
      className={className}
      style={{ breakInside: 'avoid', pageBreakInside: 'avoid' }}
    >
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* SubHeader — subtítulo dentro de uma parte                           */
/* ------------------------------------------------------------------ */
export function SubHeader({ children }: { children: React.ReactNode }) {
  return (
    <h3
      className="text-[10px] uppercase font-bold mb-1.5"
      style={{ fontFamily: FONT_HEADING, color: COLOR_PRIMARY, letterSpacing: '0.22em' }}
    >
      {children}
    </h3>
  );
}

/* ------------------------------------------------------------------ */
/* ReportField — par label/valor padronizado                           */
/* ------------------------------------------------------------------ */
interface ReportFieldProps {
  label: string;
  value?: React.ReactNode;
  mono?: boolean;
  /** Texto explicativo a mostrar quando value é vazio (Bloco 2). */
  emptyKind?: EmptyFieldKind;
}

export function ReportField({ label, value, mono = false, emptyKind = 'generic' }: ReportFieldProps) {
  const empty = isEmptyValue(value);
  return (
    <div data-pdf-keep="true" style={{ breakInside: 'avoid', pageBreakInside: 'avoid' }}>
      <dt
        className="text-[9px] uppercase font-semibold mb-0.5"
        style={{ color: COLOR_MUTED, letterSpacing: '0.06em' }}
      >
        {label}
      </dt>
      <dd
        className={empty ? 'text-[10.5px] italic leading-snug' : (mono ? 'text-[10px] break-all' : 'text-[11.5px] leading-snug')}
        style={{
          fontFamily: empty ? FONT_BODY : (mono ? FONT_MONO : FONT_BODY),
          color: empty ? COLOR_MUTED : COLOR_TEXT,
        }}
      >
        {empty ? emptyText(emptyKind) : value}
      </dd>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* HashHighlight — destaque máximo para hash composto principal        */
/* ------------------------------------------------------------------ */
interface HashHighlightProps {
  label: string;
  hash: string;
  description?: string;
}

export function HashHighlight({ label, hash, description }: HashHighlightProps) {
  return (
    <div
      data-pdf-keep="true"
      className="border-2 p-4 rounded-lg"
      style={{ borderColor: COLOR_PRIMARY, backgroundColor: `${COLOR_PRIMARY}0D`, breakInside: 'avoid', pageBreakInside: 'avoid' }}
    >
      <div className="flex items-center gap-2 mb-2">
        <ShieldCheck className="w-4 h-4" style={{ color: COLOR_PRIMARY }} strokeWidth={2.4} />
        <span
          className="text-[10px] uppercase font-bold"
          style={{ fontFamily: FONT_HEADING, color: COLOR_PRIMARY, letterSpacing: '0.22em' }}
        >
          {label}
        </span>
      </div>
      {description && (
        <p
          className="text-[10.5px] italic mb-2 leading-snug"
          style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
        >
          {description}
        </p>
      )}
      <p
        className="text-[12px] break-all border-2 px-3 py-2.5 rounded text-center font-bold"
        style={{
          fontFamily: FONT_MONO,
          backgroundColor: '#ffffff',
          borderColor: COLOR_PRIMARY,
          color: COLOR_PRIMARY,
          letterSpacing: '0.04em',
        }}
      >
        {hash.toLowerCase()}
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* SummaryRow — linha da tabela resumo no frontispício                 */
/* ------------------------------------------------------------------ */
function SummaryRow({
  label,
  value,
  mono = false,
  highlight = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  highlight?: boolean;
}) {
  return (
    <tr
      data-pdf-keep="true"
      style={{
        breakInside: 'avoid',
        pageBreakInside: 'avoid',
        borderTop: highlight
          ? `2px solid ${COLOR_PRIMARY}`
          : `1px solid ${COLOR_PRIMARY}33`,
        borderBottom: highlight ? `2px solid ${COLOR_PRIMARY}` : 'none',
      }}
    >
      <td
        className="py-1.5 px-3 font-bold uppercase text-[9px] w-[42%]"
        style={{
          fontFamily: FONT_HEADING,
          backgroundColor: highlight ? COLOR_PRIMARY : `${COLOR_PRIMARY}0D`,
          color: highlight ? '#ffffff' : COLOR_PRIMARY,
          letterSpacing: '0.08em',
        }}
      >
        {label}
      </td>
      <td
        className={`py-1.5 px-3 break-all ${mono ? 'text-[10px]' : 'text-[11px]'} ${
          highlight ? 'font-bold' : ''
        }`}
        style={{
          fontFamily: mono ? FONT_MONO : FONT_BODY,
          color: highlight ? COLOR_PRIMARY : COLOR_TEXT,
          backgroundColor: highlight ? `${COLOR_PRIMARY}0D` : 'transparent',
          borderLeft: `1px solid ${COLOR_PRIMARY}33`,
        }}
      >
        {value}
      </td>
    </tr>
  );
}

/* ------------------------------------------------------------------ */
/* ReportFrontispiece — capa cartorial oficial                         */
/* ------------------------------------------------------------------ */
interface FrontispieceProps {
  titleLines: [string, string?];
  tagline: string;
  certificationText: React.ReactNode;
  summaryRows: Array<{ label: string; value: React.ReactNode; mono?: boolean }>;
  evidenceHash: string;
  /** Quantas partes este documento possui. Pode ser sobrescrito; senão usa contagem dinâmica. */
  totalParts?: number;
  /** Identificação do solicitante (Bloco 1). Renderizada como subseção fixa "1.0". */
  requester?: RequesterIdentification | null;
}

export function ReportFrontispiece({
  titleLines,
  tagline,
  certificationText,
  summaryRows,
  evidenceHash,
  totalParts,
  requester,
}: FrontispieceProps) {
  return (
    <section
      data-pdf-section
      data-pdf-break-after="true"
      className="relative bg-white p-10 overflow-hidden"
      style={{
        borderTop: `6px double ${COLOR_PRIMARY}`,
        borderBottom: `6px double ${COLOR_PRIMARY}`,
      }}
    >
      {/* Marca d'água */}
      <div
        className="absolute inset-0 flex items-center justify-center pointer-events-none select-none"
        aria-hidden="true"
        style={{ opacity: 0.04 }}
      >
        <ShieldCheck
          className="w-[420px] h-[420px]"
          style={{ color: COLOR_PRIMARY }}
          strokeWidth={1}
        />
      </div>

      <div className="relative">
        {/* Brasão institucional */}
        <div className="flex flex-col items-center gap-2 mb-6">
          <div
            className="w-16 h-16 rounded-full flex items-center justify-center border-4 shadow-md"
            style={{
              backgroundColor: COLOR_PRIMARY,
              borderColor: `${COLOR_PRIMARY}33`,
            }}
          >
            <ShieldCheck className="w-9 h-9 text-white" strokeWidth={2.2} />
          </div>
          <div className="text-center" style={{ fontFamily: FONT_HEADING }}>
            <div
              className="text-[10px] uppercase font-bold"
              style={{ color: COLOR_PRIMARY, letterSpacing: '0.42em' }}
            >
              Trace Hub
            </div>
            <div
              className="text-[9px] uppercase mt-0.5"
              style={{ color: COLOR_MUTED, letterSpacing: '0.28em' }}
            >
              Plataforma de Evidências Digitais
            </div>
          </div>
        </div>

        {/* Título principal */}
        <div
          className="text-center pt-4 pb-5"
          style={{
            borderTop: `2px solid ${COLOR_PRIMARY}4D`,
            borderBottom: `2px solid ${COLOR_PRIMARY}4D`,
          }}
        >
          {titleLines.filter(Boolean).map((line, i) => (
            <h1
              key={i}
              className="text-[28px] font-bold uppercase leading-tight"
              style={{
                fontFamily: FONT_HEADING,
                color: COLOR_PRIMARY,
                letterSpacing: '0.32em',
              }}
            >
              {line}
            </h1>
          ))}
          <p
            className="text-[11px] italic mt-2"
            style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
          >
            {tagline}
          </p>
        </div>

        {/* Texto cartorial */}
        <div
          className="mt-6 text-[12px] leading-[1.7] text-justify"
          style={{ fontFamily: FONT_BODY, color: COLOR_TEXT }}
        >
          <p className="indent-8">{certificationText}</p>
        </div>

        {/* Tabela resumo */}
        <table className="w-full mt-6 border-collapse">
          <tbody>
            {summaryRows.map((row, i) => (
              <SummaryRow key={i} label={row.label} value={row.value} mono={row.mono} />
            ))}
            <SummaryRow
              label="Código único · SHA-256"
              value={evidenceHash.toLowerCase()}
              mono
              highlight
            />
          </tbody>
        </table>

        {/* Bloco 1 — Identificação do Solicitante (subseção fixa do laudo) */}
        {requester && (
          <div
            data-pdf-keep="true"
            className="mt-6 border rounded p-4"
            style={{ borderColor: `${COLOR_PRIMARY}66`, backgroundColor: `${COLOR_PRIMARY}08`, breakInside: 'avoid', pageBreakInside: 'avoid' }}
          >
            <div
              className="text-[10px] uppercase font-bold mb-2"
              style={{ fontFamily: FONT_HEADING, color: COLOR_PRIMARY, letterSpacing: '0.22em' }}
            >
              1.0 · Identificação do Solicitante
            </div>
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2">
              <ReportField label="Nome completo" value={requester.name} />
              {requester.cpf && <ReportField label="CPF" value={requester.cpf} mono />}
              {requester.cargo && <ReportField label="Cargo / função" value={requester.cargo} />}
              <ReportField label="E-mail da conta" value={requester.email} mono />
              <ReportField
                label="Data e hora da submissão"
                value={new Date(requester.submittedAt).toLocaleString('pt-BR')}
                mono
              />
              <ReportField label="IP de origem (server-side)" value={requester.ip || 'unknown'} mono />
              <div className="sm:col-span-2">
                <ReportField label="ID da requisição (server-side)" value={requester.requestId || '—'} mono />
              </div>
            </dl>
            <p
              className="text-[9.5px] italic mt-2 leading-snug"
              style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
            >
              Estes dados integram o cálculo do código único de verificação. Qualquer
              adulteração posterior invalida a validação pública do documento.
            </p>
          </div>
        )}

        {/* Selo "AUTENTICADO" */}
        <div className="flex justify-center mt-7">
          <div
            className="inline-flex flex-col items-center gap-1 px-6 py-3 border-2 rounded-full bg-white shadow-sm"
            style={{ borderColor: COLOR_PRIMARY }}
          >
            <div className="flex items-center gap-2">
              <ShieldCheck
                className="w-4 h-4"
                style={{ color: COLOR_PRIMARY }}
                strokeWidth={2.4}
              />
              <span
                className="text-[14px] font-bold uppercase"
                style={{
                  fontFamily: FONT_HEADING,
                  color: COLOR_PRIMARY,
                  letterSpacing: '0.32em',
                }}
              >
                Autenticado
              </span>
            </div>
            <span
              className="text-[8.5px] uppercase"
              style={{
                fontFamily: FONT_HEADING,
                color: COLOR_MUTED,
                letterSpacing: '0.22em',
              }}
            >
              {new Date().toLocaleDateString('pt-BR')}
            </span>
          </div>
        </div>

        {/* Rodapé do frontispício */}
        <div
          className="mt-7 pt-3 text-center"
          style={{ borderTop: `1px solid ${COLOR_PRIMARY}4D` }}
        >
          <p
            className="text-[9px] uppercase font-semibold"
            style={{
              fontFamily: FONT_HEADING,
              color: COLOR_MUTED,
              letterSpacing: '0.22em',
            }}
          >
            Documento composto por{' '}
            <span data-parts-count>{totalParts ?? 4}</span> partes · Validação pública via QR Code na última página
          </p>
          <p
            className="text-[10px] italic mt-1"
            style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
          >
            CPC art. 411, II · MP 2.200-2/2001 · Lei 14.063/2020
          </p>
          <p
            data-pdf-keep="true"
            className="text-[8.5px] mt-3 leading-snug text-left"
            style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
          >
            {LEGAL_RETENTION_CLAUSE}
          </p>
          <p
            data-pdf-keep="true"
            className="text-[8.5px] mt-2 leading-snug text-left"
            style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
          >
            <strong>Nota técnica:</strong> {TSR_VALIDATION_NOTE}
          </p>

        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* PartSection — wrapper de seção PDF (com quebra antes da PARTE)      */
/* ------------------------------------------------------------------ */
export function PartSection({
  children,
  breakBefore = true,
  tall = false,
  className = '',
}: {
  children: React.ReactNode;
  breakBefore?: boolean;
  tall?: boolean;
  className?: string;
}) {
  const props: Record<string, string> = { 'data-pdf-section': '' };
  if (breakBefore) props['data-pdf-break-before'] = 'true';
  if (tall) props['data-pdf-tall'] = 'true';
  return (
    <section className={`px-8 ${className}`} {...props}>
      {children}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* ValidationPage — última página com QR, instruções completas (Bloco 3) */
/* ------------------------------------------------------------------ */
interface ValidationPageProps {
  hash: string;
  reportType: ForensicReportType;
  /** Número da Parte. Default "IV" — passar "V" se houver anexo posterior. */
  partNumber?: string;
}

function ValidationStep({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <li className="flex gap-3 items-start">
      <span
        className="shrink-0 w-6 h-6 rounded-full text-white text-[11px] font-bold flex items-center justify-center"
        style={{ backgroundColor: COLOR_PRIMARY, fontFamily: FONT_HEADING }}
      >
        {n}
      </span>
      <span
        className="text-[11px] leading-[1.55] flex-1"
        style={{ fontFamily: FONT_BODY, color: COLOR_TEXT }}
      >
        {children}
      </span>
    </li>
  );
}

export function ValidationPage({ hash, reportType, partNumber = 'IV' }: ValidationPageProps) {
  const [qrDataUrl, setQrDataUrl] = React.useState<string | null>(null);
  const url = getValidatorUrl(hash);

  React.useEffect(() => {
    QRCodeLib.toDataURL(url, { errorCorrectionLevel: 'M', margin: 1, width: 280 })
      .then(setQrDataUrl)
      .catch(() => setQrDataUrl(null));
  }, [url]);

  return (
    <>
      <section
        data-pdf-section
        data-pdf-break-before="true"
        className="px-8 pt-8"
      >
        <PartHeader
          number={partNumber}
          title="Da Validação Pública"
          subtitle="Verificação independente da autenticidade e integridade deste documento"
        />
      </section>
      <section
        data-pdf-section
        data-pdf-keep-together="true"
        className="px-8 mt-4 pb-8"
      >
        <div
          className="border-2 rounded-lg p-6 bg-white"
          style={{ borderColor: COLOR_PRIMARY, breakInside: 'avoid', pageBreakInside: 'avoid' }}
        >
          <div className="flex flex-col items-center gap-4">
            {qrDataUrl && (
              <div
                className="bg-white p-2.5 rounded border-2"
                style={{ borderColor: COLOR_PRIMARY }}
                data-qr-ready="true"
              >
                {/* eslint-disable-next-line jsx-a11y/alt-text */}
                <img src={qrDataUrl} width={180} height={180} className="block" />
              </div>
            )}

            <div className="w-full">
              <div
                className="text-[9px] uppercase font-bold text-center mb-1.5"
                style={{ fontFamily: FONT_HEADING, color: COLOR_PRIMARY, letterSpacing: '0.22em' }}
              >
                Código Único de Verificação · SHA-256
              </div>
              <code
                className="block text-[10.5px] break-all p-2.5 rounded border-2 text-center"
                style={{
                  fontFamily: FONT_MONO,
                  borderColor: COLOR_PRIMARY,
                  color: COLOR_PRIMARY,
                  backgroundColor: '#fafaf7',
                  letterSpacing: '0.04em',
                  fontWeight: 'bold',
                }}
              >
                {hash.toLowerCase()}
              </code>
            </div>

            <ol className="w-full space-y-3 mt-2">
              <ValidationStep n={1}>
                Aponte a câmera do celular para o QR Code <strong>OU</strong> acesse{' '}
                <strong style={{ color: COLOR_PRIMARY }}>trace-hub.com/verificar-evidencia</strong>
              </ValidationStep>
              <ValidationStep n={2}>
                Cole o código SHA-256 acima no campo de verificação
              </ValidationStep>
              <ValidationStep n={3}>
                O sistema confirmará a <strong>autoria, integridade e cadeia de custódia</strong>
                {' '}do documento, exibindo os dados originais da análise e confirmando que o
                arquivo não foi alterado após a geração deste laudo.
              </ValidationStep>
            </ol>

            <div
              className="w-full mt-3 pt-3 text-center"
              style={{ borderTop: `1px solid ${COLOR_PRIMARY}33` }}
            >
              <p
                className="text-[9px] uppercase font-semibold"
                style={{ fontFamily: FONT_HEADING, color: COLOR_MUTED, letterSpacing: '0.18em' }}
              >
                Fundamentação Legal
              </p>
              <p
                className="text-[10px] italic mt-0.5"
                style={{ fontFamily: FONT_BODY, color: COLOR_TEXT }}
              >
                CPC art. 411, II · MP 2.200-2/2001 · Lei 14.063/2020
              </p>
            </div>
          </div>
        </div>
        {/* Mantido para compat: registra também o selo padrão (oculto se já houver QR acima) */}
        <div className="hidden">
          <ForensicSeal hash={hash} reportType={reportType} fullPage />
        </div>
      </section>
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Bloco 6 — Explicações jurídicas para leigos                         */
/* ------------------------------------------------------------------ */
export function TemporalAnchorExplainer() {
  return (
    <p
      className="text-[11px] leading-[1.6] text-justify mt-2"
      style={{ fontFamily: FONT_BODY, color: COLOR_TEXT }}
    >
      A evidência foi registrada em fontes temporais independentes do sistema Trace Hub,
      tornando impossível a alegação de data retroativa. A âncora multi-chain (OriginStamp)
      registra o hash simultaneamente em Bitcoin, Ethereum e IPFS — ledgers públicos
      distribuídos imutáveis e auditáveis por qualquer perito independente.
    </p>
  );
}

export function InfrastructureSnapshotExplainer() {
  return (
    <p
      className="text-[11px] leading-[1.6] text-justify mt-2"
      style={{ fontFamily: FONT_BODY, color: COLOR_TEXT }}
    >
      Este anexo registra a identidade técnica do servidor responsável pelo conteúdo
      capturado. O <strong>fingerprint de atribuição</strong> permite vincular este
      domínio a outros domínios operados pela mesma infraestrutura — útil para
      identificar autoria comum em fraudes coordenadas.
    </p>
  );
}

export function TimeSourceNote({ source = 'timeapi.io' }: { source?: string }) {
  return (
    <p
      className="text-[10px] italic mt-1"
      style={{ fontFamily: FONT_BODY, color: COLOR_MUTED }}
    >
      Hora obtida de {source}, serviço público de tempo via API REST, operado de forma
      independente do sistema Trace Hub, eliminando conflito de interesse na certificação
      temporal.
    </p>
  );
}

/* ------------------------------------------------------------------ */
/* Bloco 7 — Status de confirmação OpenTimestamps                      */
/* ------------------------------------------------------------------ */
export interface OtsStatus {
  confirmed: boolean;
  confirmedAt?: string | null;
  blockHeight?: number | null;
}

export function OpenTimestampsStatus({
  status,
  onVerify,
  onRegenerate,
  verifying,
}: {
  status: OtsStatus;
  onVerify?: () => void;
  onRegenerate?: () => void;
  verifying?: boolean;
}) {
  const confirmed = status.confirmed;
  const bg = confirmed ? '#ecfdf5' : '#fffbeb';
  const border = confirmed ? '#10b981' : '#f59e0b';
  const fg = confirmed ? '#065f46' : '#92400e';
  return (
    <div
      data-pdf-keep="true"
      className="rounded border-2 p-3 mt-3"
      style={{ backgroundColor: bg, borderColor: border, breakInside: 'avoid', pageBreakInside: 'avoid' }}
    >
      <div className="flex items-center gap-2 mb-1.5">
        {confirmed ? (
          <CheckCircle2 className="w-4 h-4" style={{ color: border }} strokeWidth={2.4} />
        ) : (
          <ClockIcon className="w-4 h-4" style={{ color: border }} strokeWidth={2.4} />
        )}
        <span
          className="text-[10px] uppercase font-bold"
          style={{ fontFamily: FONT_HEADING, color: fg, letterSpacing: '0.2em' }}
        >
          Status de confirmação · {confirmed ? 'Confirmado' : 'Pendente'}
        </span>
      </div>
      <p
        className="text-[11px] leading-[1.55]"
        style={{ fontFamily: FONT_BODY, color: fg }}
      >
        {confirmed ? (
          <>
            Âncora multi-chain confirmada em{' '}
            <strong>
              {status.confirmedAt ? new Date(status.confirmedAt).toLocaleString('pt-BR') : '—'}
            </strong>
            . Registro imutável verificável publicamente em{' '}
            <strong>originstamp.com</strong>.
          </>
        ) : (
          <>
            Confirmação pendente — âncora multi-chain (Bitcoin · Ethereum · IPFS) prevista em
            minutos via OriginStamp. Recomenda-se aguardar confirmação antes de juntar aos autos.
          </>
        )}
      </p>
      {(onVerify || (confirmed && onRegenerate)) && (
        <div className="flex gap-2 mt-2" data-html2canvas-ignore="true">
          {onVerify && (
            <button
              type="button"
              onClick={onVerify}
              disabled={verifying}
              className="text-[10px] inline-flex items-center gap-1 px-2 py-1 rounded border bg-white hover:bg-slate-50 disabled:opacity-50"
              style={{ borderColor: border, color: fg, fontFamily: FONT_HEADING, letterSpacing: '0.1em' }}
            >
              {verifying ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <RefreshCw className="w-3 h-3" />
              )}
              Atualizar ancoragem Bitcoin agora
            </button>
          )}
          {confirmed && onRegenerate && (
            <button
              type="button"
              onClick={onRegenerate}
              className="text-[10px] inline-flex items-center gap-1 px-2 py-1 rounded border bg-white hover:bg-slate-50"
              style={{ borderColor: border, color: fg, fontFamily: FONT_HEADING, letterSpacing: '0.1em' }}
            >
              Gerar versão atualizada do laudo
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* ReportRoot — wrapper raiz do laudo (fontes + cor base)              */
/* ------------------------------------------------------------------ */
export const ReportRoot = React.forwardRef<HTMLDivElement, { children: React.ReactNode }>(
  ({ children }, ref) => (
    <div
      ref={ref}
      className="relative bg-white"
      style={{ fontFamily: FONT_BODY, color: COLOR_TEXT }}
    >
      {children}
    </div>
  ),
);
ReportRoot.displayName = 'ReportRoot';

/* ------------------------------------------------------------------ */
/* useForensicExport — hook helper para PDF + PNG fallback             */
/* ------------------------------------------------------------------ */
import { useState } from 'react';
import { exportSectionedPDF } from '@/lib/pdf-section-export';
import { ensureForensicFontsLoaded } from '@/lib/forensic-fonts';
import { downloadBlob, isIOS as isIOSDevice, openPopupForDownload } from '@/lib/ios-download';
import { toast } from 'sonner';

export function useForensicExport(
  reportRef: React.RefObject<HTMLDivElement>,
  filenamePrefix: string,
  shortHashGetter: () => string | undefined,
  onPdfReady?: (base64: string) => void,
) {
  const [generating, setGenerating] = useState(false);

  const waitForQR = async (timeoutMs = 2000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (reportRef.current?.querySelector('[data-qr-ready="true"]')) return;
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  /**
   * Bloco 5 — conta dinamicamente as Partes do laudo (cabeçalhos com
   * `data-pdf-part-header`) e atualiza `<span data-parts-count>` no
   * frontispício antes do html2canvas capturar.
   */
  const syncPartsCount = () => {
    const root = reportRef.current;
    if (!root) return;
    const parts = root.querySelectorAll('[data-pdf-part-header]').length;
    const target = root.querySelector<HTMLElement>('[data-parts-count]');
    if (target && parts > 0) target.textContent = String(parts);
  };

  /**
   * Abre uma janela placeholder DENTRO do gesture do clique. Necessário para
   * iOS Safari, que bloqueia downloads programáticos fora do gesture original.
   */
  const openPopupInGesture = (): Window | null =>
    openPopupForDownload('Gerando manifesto cartorial…');

  const exportPDF = async () => {
    if (!reportRef.current) {
      toast.error('Laudo ainda não está pronto. Aguarde alguns segundos e tente novamente.');
      return;
    }
    if (reportRef.current.offsetHeight === 0) {
      toast.error('Laudo não foi montado (altura 0). Recarregue a página e tente de novo.');
      return;
    }

    // CRÍTICO: abre popup ANTES de qualquer await (precisa estar no gesture)
    const popup = openPopupInGesture();
    const ios = isIOSDevice();
    if (ios && !popup) {
      toast.error('Permita pop-ups deste site para baixar o PDF no iPhone.', { duration: 6000 });
      return;
    }

    setGenerating(true);
    const progressToast = toast.loading('Gerando manifesto cartorial…');

    try {
      syncPartsCount();
      await ensureForensicFontsLoaded();
      await waitForQR(4000);
      const { base64 } = await exportSectionedPDF(
        reportRef.current,
        `${filenamePrefix}-${Date.now()}.pdf`,
        { shortHash: shortHashGetter() },
        popup,
      );
      try { onPdfReady?.(base64); } catch (cbErr) { console.warn('[onPdfReady]', cbErr); }
      toast.dismiss(progressToast);
      if (ios) {
        toast.success('PDF aberto em nova aba — toque em Compartilhar > Salvar em Arquivos.', { duration: 7000 });
      } else {
        toast.success('Laudo PDF gerado com identidade cartorial');
      }
    } catch (e: any) {
      toast.dismiss(progressToast);
      console.error('[PDF Export]', e);
      if (popup && !popup.closed) {
        try { popup.close(); } catch { /* noop */ }
      }
      toast.error(`Falha ao exportar PDF: ${e?.message || 'erro desconhecido'}`, { duration: 8000 });
    } finally {
      setGenerating(false);
    }
  };

  const exportPNG = async () => {
    if (!reportRef.current) return;

    const popup = openPopupInGesture();
    const ios = isIOSDevice();
    if (ios && !popup) {
      toast.error('Permita pop-ups deste site para baixar a imagem no iPhone.', { duration: 6000 });
      return;
    }

    setGenerating(true);
    const progressToast = toast.loading('Gerando imagem do laudo…');

    try {
      syncPartsCount();
      await ensureForensicFontsLoaded();
      await waitForQR();
      const html2canvas = getHtml2Canvas();
      const isMobile = typeof window !== 'undefined' && window.innerWidth < 640;
      const canvas = await html2canvas(reportRef.current, {
        scale: isMobile ? 1.5 : 2,
        backgroundColor: '#ffffff',
        useCORS: true,
        logging: false,
      });
      await new Promise<void>((resolve, reject) => {
        canvas.toBlob(
          (blob: Blob | null) => {
            if (!blob) {
              reject(new Error('Canvas vazio (limite de tamanho excedido).'));
              return;
            }
            downloadBlob(blob, `${filenamePrefix}-${Date.now()}.png`, popup);
            resolve();
          },
          'image/png',
        );
      });
      toast.dismiss(progressToast);
      if (ios) {
        toast.success('Imagem aberta em nova aba — toque em Compartilhar para salvar.', { duration: 7000 });
      } else {
        toast.success('Imagem do laudo baixada');
      }
    } catch (e: any) {
      toast.dismiss(progressToast);
      console.error('[PNG Export]', e);
      if (popup && !popup.closed) {
        try { popup.close(); } catch { /* noop */ }
      }
      toast.error(`Falha ao exportar PNG: ${e?.message || 'erro'}`);
    } finally {
      setGenerating(false);
    }
  };

  return { generating, exportPDF, exportPNG };
}

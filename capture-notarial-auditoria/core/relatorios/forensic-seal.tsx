/**
 * Selo de Autenticidade Trace Hub
 *
 * Componente React para renderizar o selo no rodapé de qualquer laudo gerado
 * via html2canvas, e função utilitária para registrar o laudo na tabela
 * `forensic_reports` (lookup central do validador).
 */
import { useEffect, useState } from 'react';
import { Lock, ShieldCheck } from 'lucide-react';
import QRCode from 'qrcode';
import { supabase } from '@/integrations/supabase/client';

const VALIDATOR_BASE = 'https://www.trace-hub.com/verificar-evidencia';

export type ForensicReportType =
  | 'metadata_decoder'
  | 'selective_capture'
  | 'screen_recording'
  | 'notarial'
  | 'chain_of_custody';

const TYPE_LABEL: Record<ForensicReportType | string, string> = {
  metadata_decoder: 'Decoder de Metadados',
  selective_capture: 'Recorte Notarial',
  screen_recording: 'Gravação de Tela',
  notarial: 'Ata Notarial Digital',
  chain_of_custody: 'Cadeia de Custódia',
  link_capture: 'Captura de Evidência Digital',
};

export function getReportTypeLabel(type?: string | null): string {
  if (!type) return 'Evidência Forense';
  return TYPE_LABEL[type] ?? type;
}

/**
 * Registra um laudo na tabela central `forensic_reports`.
 * Falha silenciosamente (laudo segue sendo gerado mesmo offline).
 */
export async function registerForensicReport(input: {
  evidenceHash: string;
  reportType: ForensicReportType;
  subject?: string;
  metadata?: Record<string, any>;
}): Promise<void> {
  try {
    const { data: userResp } = await supabase.auth.getUser();
    const userId = userResp?.user?.id;
    if (!userId) return; // só registra para autenticados; selo continua valendo via hash

    await (supabase.from('forensic_reports') as any).upsert(
      {
        user_id: userId,
        evidence_hash: input.evidenceHash.toLowerCase(),
        report_type: input.reportType,
        subject: input.subject ?? null,
        metadata: input.metadata ?? {},
      },
      { onConflict: 'evidence_hash', ignoreDuplicates: true },
    );
  } catch (err) {
    console.warn('[forensic-seal] registro falhou (não bloqueante)', err);
  }
}

/**
 * Registra um complemento de metadados do laudo (ex.: SHA-256 do PDF gerado
 * depois do registro inicial).
 *
 * `forensic_reports` é WORM/append-only (trigger bloqueia UPDATE), então o
 * complemento é gravado como evento append-only em `forensic_report_stamps`.
 */
export async function updateForensicReportMetadata(
  evidenceHash: string,
  patch: Record<string, any>,
): Promise<void> {
  try {
    const { data: userResp } = await supabase.auth.getUser();
    const userId = userResp?.user?.id;
    if (!userId) return;
    const { error } = await (supabase.from('forensic_report_stamps') as any).insert({
      user_id: userId,
      evidence_hash: evidenceHash.toLowerCase(),
      kind: 'metadata_patch',
      payload: patch ?? {},
    });
    if (error) throw error;
  } catch (err) {
    console.warn('[forensic-seal] update metadata falhou (não bloqueante)', err);
  }
}


export function getValidatorUrl(hash: string): string {
  return `${VALIDATOR_BASE}?hash=${encodeURIComponent(hash.toLowerCase())}`;
}

interface ForensicSealProps {
  hash: string;
  reportType: ForensicReportType;
  className?: string;
  /** Variante "página inteira" — QR maior + instruções numeradas. Usar como última seção do PDF. */
  fullPage?: boolean;
  /** SHA-256 do PDF final (calculado após geração). Exibido apenas em fullPage. */
  pdfHash?: string | null;
}

/**
 * Selo visual padrão. Inclua dentro do `reportRef` (área que vira PDF).
 */
export function ForensicSeal({ hash, reportType, className = '', fullPage = false, pdfHash = null }: ForensicSealProps) {
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const url = getValidatorUrl(hash);
  const qrSize = fullPage ? 360 : 220;
  const qrPx = fullPage ? 200 : 120;

  useEffect(() => {
    QRCode.toDataURL(url, { errorCorrectionLevel: 'M', margin: 1, width: qrSize })
      .then(setQrDataUrl)
      .catch(() => setQrDataUrl(null));
  }, [url, qrSize]);

  if (fullPage) {
    return (
      <div
        className={`rounded-lg border-2 border-[#0F4C3A] bg-white p-6 ${className}`}
        data-forensic-seal
      >
        <div className="text-center mb-5">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0F4C3A] text-white text-[10px] font-bold uppercase tracking-[0.22em] mb-3"
               style={{ fontFamily: "'Cinzel', Georgia, serif" }}>
            <ShieldCheck className="w-3 h-3" />
            Verificação Pública
          </div>
          <h3 className="text-[16px] font-bold text-slate-900 tracking-[0.18em] uppercase"
              style={{ fontFamily: "'Cinzel', Georgia, serif" }}>
            Autenticidade do Documento
          </h3>
          <p className="text-[10px] italic text-slate-600 mt-1"
             style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
            {getReportTypeLabel(reportType)}
          </p>
        </div>

        <div className="flex flex-col items-center gap-4">
          {qrDataUrl && (
            <div
              className="bg-white p-2.5 rounded border-2 border-[#0F4C3A]"
              data-qr-ready="true"
            >
              {/* eslint-disable-next-line jsx-a11y/alt-text */}
              <img src={qrDataUrl} width={qrPx} height={qrPx} className="block" />
            </div>
          )}

          <div className="w-full max-w-md">
            <div className="text-[9px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold text-center mb-1.5"
                 style={{ fontFamily: "'Cinzel', Georgia, serif" }}>
              Código Único de Verificação · SHA-256
            </div>
            <code className="block text-[10px] font-mono break-all bg-slate-50 text-slate-900 p-2.5 rounded border-2 border-[#0F4C3A] text-center tracking-wider"
                  style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}>
              {hash.toLowerCase()}
            </code>
          </div>

          {pdfHash && (
            <div className="w-full max-w-md">
              <div className="text-[9px] uppercase tracking-[0.22em] text-[#0F4C3A] font-bold text-center mb-1.5"
                   style={{ fontFamily: "'Cinzel', Georgia, serif" }}>
                SHA-256 do documento PDF
              </div>
              <code className="block text-[10px] font-mono break-all bg-slate-50 text-slate-900 p-2.5 rounded border border-slate-300 text-center tracking-wider"
                    style={{ fontFamily: "'JetBrains Mono', Courier, monospace" }}>
                {pdfHash.toLowerCase()}
              </code>
              <p className="text-[9px] italic text-slate-500 text-center mt-1"
                 style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
                Fecha a cadeia: hash da página → hash do PDF → blockchain (OTS + RFC 3161)
              </p>
            </div>
          )}

          <ol className="w-full max-w-md space-y-1.5 text-[11px] text-slate-700 leading-snug"
              style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
            <li className="flex gap-2">
              <span className="shrink-0 w-5 h-5 rounded-full bg-[#0F4C3A] text-white text-[10px] font-bold flex items-center justify-center"
                    style={{ fontFamily: "'Cinzel', Georgia, serif" }}>1</span>
              <span>Aponte a câmera do celular para o QR Code <strong>OU</strong> acesse <strong className="text-[#0F4C3A]">trace-hub.com/verificar-evidencia</strong></span>
            </li>
            <li className="flex gap-2">
              <span className="shrink-0 w-5 h-5 rounded-full bg-[#0F4C3A] text-white text-[10px] font-bold flex items-center justify-center"
                    style={{ fontFamily: "'Cinzel', Georgia, serif" }}>2</span>
              <span>Cole o código SHA-256 acima no campo de verificação</span>
            </li>
            <li className="flex gap-2">
              <span className="shrink-0 w-5 h-5 rounded-full bg-[#0F4C3A] text-white text-[10px] font-bold flex items-center justify-center"
                    style={{ fontFamily: "'Cinzel', Georgia, serif" }}>3</span>
              <span>O sistema confirmará a <strong>autoria, integridade e cadeia de custódia</strong> do documento</span>
            </li>
          </ol>

          <div className="w-full max-w-md mt-3 pt-3 border-t border-slate-300 text-center">
            <p className="text-[9px] uppercase tracking-[0.18em] text-slate-500 font-semibold"
               style={{ fontFamily: "'Cinzel', Georgia, serif" }}>
              Fundamentação Legal
            </p>
            <p className="text-[10px] text-slate-700 italic mt-0.5"
               style={{ fontFamily: "'EB Garamond', Georgia, serif" }}>
              CPC art. 411, II · MP 2.200-2/2001 · Lei 14.063/2020
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`rounded-lg border-2 border-slate-800 bg-white p-4 ${className}`}
      data-forensic-seal
    >
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-200">
        <Lock className="w-4 h-4 text-slate-800" strokeWidth={2.4} />
        <span className="text-[11px] font-bold uppercase tracking-[0.18em] text-slate-900">
          Selo de Autenticidade — Validação Pública
        </span>
        <ShieldCheck className="w-4 h-4 text-emerald-600 ml-auto" strokeWidth={2.4} />
      </div>

      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0 space-y-2.5">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-0.5">
              Tipo de laudo
            </div>
            <div className="text-xs font-bold text-slate-900">{getReportTypeLabel(reportType)}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-0.5">
              Código de validação SHA-256
            </div>
            <code className="block text-[10px] font-mono break-all bg-slate-50 text-slate-900 p-2 rounded border border-slate-300">
              {hash.toLowerCase()}
            </code>
          </div>
          <div className="text-[10px] text-slate-600 leading-snug pt-1">
            Verifique a autenticidade deste laudo escaneando o QR Code ao lado, ou cole
            o código acima em{' '}
            <strong className="text-slate-900">trace-hub.com/verificar-evidencia</strong>.
            A confirmação prova que o documento foi emitido pela plataforma e que sua
            integridade está preservada (cadeia de custódia).
          </div>
        </div>

        {qrDataUrl && (
          <div
            className="shrink-0 bg-white p-2 rounded border-2 border-slate-800"
            data-qr-ready="true"
          >
            {/* eslint-disable-next-line jsx-a11y/alt-text */}
            <img src={qrDataUrl} width={120} height={120} className="block" />
          </div>
        )}
      </div>
    </div>
  );
}

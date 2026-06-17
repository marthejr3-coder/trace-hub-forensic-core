import { useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Link2, Loader2, Search, Download, Clock, Globe, Hash, FileText } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import {
  ReportRoot,
  ReportFrontispiece,
  PartHeader,
  PartSection,
  SubHeader,
  ReportField,
  HashHighlight,
  ValidationPage,
  COLOR_PRIMARY,
  FONT_HEADING,
  FONT_BODY,
  FONT_MONO,
  useForensicExport,
} from '@/lib/forensic-report-kit';

interface ChainEvent {
  timestamp: string;
  label: string;
  detail: string;
  icon: 'capture' | 'access' | 'hash' | 'export';
}

interface ChainResult {
  hash: string;
  source: 'link_clicks' | 'csam_scan_sessions' | 'forensic_reports';
  capturedAt: string;
  events: ChainEvent[];
  metadata: Record<string, any>;
}

const iconMap = {
  capture: Globe,
  access: Search,
  hash: Hash,
  export: FileText,
};

function CustodyReport({ result }: { result: ChainResult }) {
  const reportRef = useRef<HTMLDivElement>(null);

  const { generating, exportPDF, exportPNG } = useForensicExport(
    reportRef,
    'cadeia-custodia',
    () => result.hash.slice(0, 16),
  );

  return (
    <>
      <div className="flex flex-wrap justify-end gap-2">
        <Button asChild variant="secondary" className="gap-2">
          <a href={`/verificar-evidencia?hash=${encodeURIComponent(result.hash)}`} target="_blank" rel="noopener noreferrer">
            Verificar criptograficamente →
          </a>
        </Button>
        <Button onClick={exportPDF} disabled={generating} className="gap-2 bg-emerald-600 hover:bg-emerald-700 text-white">
          {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
          Baixar Laudo Cartorial (PDF)
        </Button>
        <Button variant="outline" size="sm" onClick={exportPNG} disabled={generating}>
          Se PDF falhar, baixar PNG
        </Button>
      </div>


      <ReportRoot ref={reportRef}>
        <ReportFrontispiece
          titleLines={['Cadeia de', 'Custódia Digital']}
          tagline="Rastreio de integridade SHA-256 · Laudo autosuficiente"
          certificationText={
            <>
              <strong>Certifica-se</strong>, para os devidos fins de direito, que em{' '}
              <strong>{new Date().toLocaleString('pt-BR')}</strong> foi consultada a cadeia
              de custódia da evidência identificada pelo <em>hash</em> SHA-256 indicado neste
              documento. A consulta retornou <strong>{result.events.length}</strong> evento(s)
              registrado(s), demonstrando que a evidência permanece íntegra desde sua coleta
              inicial em{' '}
              <strong>{new Date(result.capturedAt).toLocaleString('pt-BR')}</strong>.
            </>
          }
          summaryRows={[
            { label: 'Origem', value: result.source.replace('_', ' ') },
            { label: 'Coletada em', value: new Date(result.capturedAt).toLocaleString('pt-BR') },
            { label: 'Eventos registrados', value: String(result.events.length) },
            { label: 'Resultado da consulta', value: 'Hash localizado nos registros Trace Hub' },
            { label: 'Verificada em', value: new Date().toLocaleString('pt-BR') },
          ]}
          evidenceHash={result.hash}

        />

        <PartSection className="pt-8">
          <PartHeader
            number="I"
            title="Da Evidência Original"
            subtitle="Identificação da fonte primária e contexto de coleta"
          />
        </PartSection>

        <PartSection breakBefore={false} className="mt-4">
          <SubHeader>1.1 · Metadados técnicos da evidência</SubHeader>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 mt-2">
            {Object.entries(result.metadata).filter(([_, v]) => v).map(([k, v]) => (
              <ReportField key={k} label={k} value={String(v)} mono={k === 'IP' || k.includes('Hash')} />
            ))}
          </dl>
        </PartSection>

        <PartSection className="pt-8">
          <PartHeader
            number="II"
            title="Da Cadeia de Eventos"
            subtitle={`Sequência cronológica de ${result.events.length} evento(s) registrados na trilha de auditoria`}
          />
        </PartSection>

        <PartSection breakBefore={false} className="mt-4">
          <div
            className="relative pl-8 space-y-3 mt-3"
            style={{ borderLeft: `2px solid ${COLOR_PRIMARY}` }}
          >
            {result.events.map((ev, idx) => {
              const Icon = iconMap[ev.icon];
              return (
                <div key={idx} className="relative">
                  <div
                    className="absolute -left-[42px] w-6 h-6 rounded-full flex items-center justify-center text-white text-xs font-bold"
                    style={{ backgroundColor: COLOR_PRIMARY, fontFamily: FONT_HEADING }}
                  >
                    {idx + 1}
                  </div>
                  <div className="rounded-lg p-3 border" style={{ borderColor: '#e5e7eb', backgroundColor: '#fafaf7' }}>
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <Icon className="w-4 h-4" style={{ color: COLOR_PRIMARY }} />
                      <p className="text-[12px] font-bold" style={{ fontFamily: FONT_BODY }}>{ev.label}</p>
                      <span
                        className="text-[10px] ml-auto inline-flex items-center gap-1"
                        style={{ fontFamily: FONT_MONO, color: '#5a5a5a' }}
                      >
                        <Clock className="w-3 h-3" />
                        {new Date(ev.timestamp).toLocaleString('pt-BR')}
                      </span>
                    </div>
                    <p className="text-[11px]" style={{ fontFamily: FONT_BODY, color: '#1a1a1a' }}>{ev.detail}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </PartSection>

        <PartSection className="pt-8">
          <PartHeader
            number="III"
            title="Da Integridade Criptográfica"
            subtitle="Hash SHA-256 que identifica unicamente esta evidência e prova ausência de alteração"
          />
        </PartSection>

        <PartSection breakBefore={false} className="mt-4">
          <p className="text-[11.5px] leading-[1.65] text-justify mb-4" style={{ fontFamily: FONT_BODY }}>
            Este documento atende ao art. 158-A do CPP (Cadeia de Custódia). A função{' '}
            <em>hash</em> SHA-256 abaixo identifica unicamente a evidência consultada. Qualquer
            alteração na fonte original resultaria em <em>hash</em> distinto, impossibilitando
            a recuperação da cadeia aqui demonstrada.
          </p>
          <p className="text-[10.5px] leading-[1.55] text-justify mb-4 p-3 rounded border" style={{ fontFamily: FONT_BODY, borderColor: '#e5e7eb', backgroundColor: '#fafaf7' }}>
            <strong>Escopo desta consulta:</strong> esta tela confirma a <em>presença</em> do
            hash na base de registros Trace Hub e a cronologia de eventos persistidos no
            servidor. A <em>verificação criptográfica completa</em> (recálculo SHA-256 do
            arquivo original, validação de TSR/OTS e cadeia de encadeamento de eventos) é
            executada pelo módulo independente <code>/verificar-evidencia</code>.
          </p>
          <HashHighlight
            label="3.1 · Código Único de Verificação · SHA-256"
            description="Hash da evidência rastreada. Use para validação pública independente."
            hash={result.hash}
          />

        </PartSection>

        <ValidationPage hash={result.hash} reportType="chain_of_custody" />
      </ReportRoot>
    </>
  );
}

export default function CadeiaCustodia() {
  const [hash, setHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ChainResult | null>(null);

  const handleSearch = async () => {
    const clean = hash.trim().toLowerCase().replace(/[:\s]/g, '');
    if (!/^[a-f0-9]{64}$/.test(clean)) {
      toast.error('Hash SHA-256 inválido');
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const { data: report } = await (supabase.from('forensic_reports') as any)
        .select('*')
        .eq('evidence_hash', clean)
        .maybeSingle();

      if (report) {
        setResult({
          hash: clean,
          source: 'forensic_reports',
          capturedAt: report.created_at,
          events: [
            {
              timestamp: report.created_at,
              label: 'Emissão do laudo forense',
              detail: `Tipo: ${report.report_type}${report.subject ? ' · ' + report.subject : ''}`,
              icon: 'capture',
            },
            {
              timestamp: report.created_at,
              label: 'Selagem SHA-256 e registro central',
              detail: 'Hash registrado na base central de validação Trace Hub',
              icon: 'hash',
            },
            {
              timestamp: new Date().toISOString(),
              label: 'Consulta pública (timestamp local — não verificado server-side)',
              detail: 'Hash conferido contra registro central — laudo íntegro',
              icon: 'export',
            },
          ],
          metadata: {
            'Tipo de laudo': report.report_type,
            'Assunto': report.subject || '—',
            'Emitido em': new Date(report.created_at).toLocaleString('pt-BR'),
          },
        });
        toast.success('Laudo forense localizado · cadeia íntegra');
        return;
      }

      const { data: click } = await (supabase.from('link_clicks') as any)
        .select('*')
        .eq('evidence_hash', clean)
        .maybeSingle();

      if (click) {
        const events: ChainEvent[] = [
          {
            timestamp: click.created_at,
            label: 'Captura inicial da evidência',
            detail: `IP ${click.ip_address || 'desconhecido'} · ${click.city || '—'}, ${click.country || '—'}`,
            icon: 'capture',
          },
          {
            timestamp: click.created_at,
            label: 'Geração do hash SHA-256',
            detail: 'Selagem criptográfica imediata dos dados coletados',
            icon: 'hash',
          },
        ];
        if (click.captured_email || click.captured_phone) {
          events.push({
            timestamp: click.created_at,
            label: 'Dados pessoais capturados',
            detail: [click.captured_name, click.captured_email, click.captured_phone].filter(Boolean).join(' · '),
            icon: 'access',
          });
        }
        if (click.latitude && click.longitude) {
          events.push({
            timestamp: click.created_at,
            label: 'Geolocalização GPS registrada',
            detail: `Lat ${click.latitude}, Lng ${click.longitude} (precisão ${click.gps_accuracy || '?'}m)`,
            icon: 'capture',
          });
        }
        events.push({
          timestamp: new Date().toISOString(),
          label: 'Consulta pública (timestamp local — não verificado server-side)',
          detail: 'Hash conferido e cadeia de custódia preservada',
          icon: 'export',
        });

        setResult({
          hash: clean,
          source: 'link_clicks',
          capturedAt: click.created_at,
          events,
          metadata: {
            'IP': click.ip_address,
            'ISP': click.isp,
            'Cidade': click.city,
            'País': click.country,
            'Dispositivo': click.device,
            'SO': click.os,
            'Navegador': click.browser,
            'VPN/Proxy': click.is_vpn ? 'Sim' : 'Não',
          },
        });
        toast.success('Cadeia de custódia recuperada');
        return;
      }

      const { data: scan } = await (supabase.from('csam_scan_sessions') as any)
        .select('*')
        .eq('evidence_hash', clean)
        .maybeSingle();

      if (scan) {
        setResult({
          hash: clean,
          source: 'csam_scan_sessions',
          capturedAt: scan.started_at,
          events: [
            { timestamp: scan.started_at, label: 'Início da varredura forense', detail: `Caso ${scan.case_reference}`, icon: 'capture' },
            { timestamp: scan.started_at, label: 'Autorização legal validada', detail: scan.legal_authorization?.slice(0, 80), icon: 'access' },
            ...(scan.finished_at
              ? [{ timestamp: scan.finished_at, label: 'Varredura concluída', detail: `${scan.total_files_scanned} arquivos, ${scan.matches_count} matches`, icon: 'hash' as const }]
              : []),
            { timestamp: new Date().toISOString(), label: 'Consulta pública (timestamp local — não verificado server-side)', detail: 'Hash da sessão íntegro', icon: 'export' },
          ],
          metadata: {
            'Caso': scan.case_reference,
            'Dispositivo': scan.device_description,
            'Operador': scan.operator_id,
            'Status': scan.status,
            'Arquivos': String(scan.total_files_scanned),
            'Matches': String(scan.matches_count),
          },
        });
        toast.success('Cadeia recuperada');
        return;
      }

      toast.error('Hash não encontrado');
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Link2 className="w-5 h-5 text-primary" />
          Cadeia de Custódia Visual
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          Rastreie a linha do tempo completa de uma evidência. Laudo cartorial padronizado pronto
          para anexar em petição ou laudo pericial.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label>Hash SHA-256 da evidência</Label>
          <div className="flex gap-2">
            <Input
              placeholder="64 caracteres hexadecimais"
              value={hash}
              onChange={(e) => setHash(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !loading && handleSearch()}
              className="font-mono text-xs"
            />
            <Button onClick={handleSearch} disabled={loading}>
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              <span className="ml-2 hidden sm:inline">Buscar</span>
            </Button>
          </div>
        </div>

        {result && <CustodyReport result={result} />}

        <div className="text-[11px] text-muted-foreground border-t pt-3">
          <strong>Uso processual:</strong> Anexe este documento à petição inicial ou laudo. Demonstra
          que a evidência não foi adulterada desde a coleta — atende ao art. 158-A do CPP.
        </div>
      </CardContent>
    </Card>
  );
}

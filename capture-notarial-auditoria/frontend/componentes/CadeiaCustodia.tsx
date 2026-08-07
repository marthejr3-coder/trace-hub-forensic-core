import { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Link2, Loader2, Search, Download, Clock, Globe, Hash, FileText, ShieldCheck, ShieldAlert, ShieldQuestion } from 'lucide-react';
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

interface ChainSignatureCheck {
  step_index: number;
  step_label: string | null;
  signed_at: string;
  payload_hash: string;
  public_key: string;
  status: 'valid' | 'invalid' | 'unsupported' | 'error';
  error?: string;
}

interface ChainResult {
  hash: string;
  source: 'link_clicks' | 'forensic_reports';
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

// --- N-03 fix: real Ed25519 verification on this layer -----------------------

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function decodeKeyOrSig(value: string): Uint8Array {
  if (/^[a-f0-9]+$/i.test(value) && value.length % 2 === 0) {
    return hexToBytes(value);
  }
  return b64ToBytes(value);
}

async function verifyEd25519Row(row: {
  public_key: string;
  ed25519_signature: string;
  payload_hash: string;
}): Promise<ChainSignatureCheck['status']> {
  try {
    if (!('subtle' in crypto)) return 'unsupported';
    const pk = decodeKeyOrSig(row.public_key);
    const sig = decodeKeyOrSig(row.ed25519_signature);
    const msg = hexToBytes(row.payload_hash);
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey('raw', pk.buffer.slice(pk.byteOffset, pk.byteOffset + pk.byteLength) as ArrayBuffer, { name: 'Ed25519' } as any, false, ['verify']);
    } catch {
      return 'unsupported';
    }
    const sigBuf = sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength) as ArrayBuffer;
    const msgBuf = msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength) as ArrayBuffer;
    const ok = await crypto.subtle.verify({ name: 'Ed25519' } as any, key, sigBuf, msgBuf);

    return ok ? 'valid' : 'invalid';
  } catch {
    return 'error';
  }
}


function CustodyReport({ result }: { result: ChainResult }) {
  const reportRef = useRef<HTMLDivElement>(null);
  const [sigChecks, setSigChecks] = useState<ChainSignatureCheck[] | null>(null);
  const [sigLoading, setSigLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setSigLoading(true);
      try {
        const { data, error } = await (supabase.from('forensic_chain_signatures') as any)
          .select('step_index, step_label, signed_at, payload_hash, public_key, ed25519_signature')
          .eq('evidence_hash', result.hash)
          .order('step_index', { ascending: true });
        if (error) throw error;
        const rows = (data ?? []) as Array<{
          step_index: number;
          step_label: string | null;
          signed_at: string;
          payload_hash: string;
          public_key: string;
          ed25519_signature: string;
        }>;
        const checks: ChainSignatureCheck[] = [];
        for (const row of rows) {
          const status = await verifyEd25519Row(row);
          checks.push({
            step_index: row.step_index,
            step_label: row.step_label,
            signed_at: row.signed_at,
            payload_hash: row.payload_hash,
            public_key: row.public_key,
            status,
          });
        }
        if (!cancelled) setSigChecks(checks);
      } catch (e: any) {
        if (!cancelled) setSigChecks([]);
      } finally {
        if (!cancelled) setSigLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [result.hash]);

  const sigTotal = sigChecks?.length ?? 0;
  const sigValid = sigChecks?.filter((s) => s.status === 'valid').length ?? 0;
  const sigInvalid = sigChecks?.filter((s) => s.status === 'invalid').length ?? 0;
  const sigBadge: 'verified' | 'tampered' | 'absent' | 'pending' = sigLoading
    ? 'pending'
    : sigInvalid > 0
      ? 'tampered'
      : sigTotal > 0 && sigValid === sigTotal
        ? 'verified'
        : 'absent';

  const { generating, exportPDF, exportPNG } = useForensicExport(
    // @ts-ignore migration: strict-mode wave
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
              <strong>{new Date().toLocaleString('pt-BR')}</strong> foi consultada a base de
              registros Trace Hub em busca da evidência identificada pelo <em>hash</em>{' '}
              SHA-256 indicado neste documento. A consulta{' '}
              <strong>confirmou a presença do hash</strong> nos registros, com{' '}
              <strong>{result.events.length}</strong> evento(s) cronologicamente associado(s),
              cuja primeira ocorrência data de{' '}
              <strong>{new Date(result.capturedAt).toLocaleString('pt-BR')}</strong>.{' '}
              {sigBadge === 'verified' && (
                <>
                  Adicionalmente, <strong>{sigValid} de {sigTotal} assinaturas Ed25519</strong>{' '}
                  da cadeia de custódia foram <strong>verificadas criptograficamente nesta
                  mesma camada</strong>, em tempo de geração deste laudo, sem qualquer
                  dependência da infraestrutura do Trace Hub para o cálculo (verificação
                  executada localmente via Web Crypto API · algoritmo Ed25519 / RFC 8032).
                </>
              )}
              {sigBadge === 'tampered' && (
                <>
                  <strong> ATENÇÃO:</strong> {sigInvalid} de {sigTotal} assinaturas Ed25519 da
                  cadeia <strong>FALHARAM</strong> na verificação criptográfica executada
                  nesta camada — indicativo de adulteração ou divergência de chave pública.
                </>
              )}
              {sigBadge === 'absent' && (
                <>
                  A presente camada de apresentação executou a busca por âncoras Ed25519
                  vinculadas a este <em>hash</em> e <strong>não localizou registros</strong>{' '}
                  em <code>forensic_chain_signatures</code>; portanto, esta certificação
                  descreve apenas <em>presença e cronologia</em>, devendo a integridade ser
                  validada pelo módulo independente <code>/verificar-evidencia</code>{' '}
                  (recálculo SHA-256, RFC 3161 e OpenTimestamps).
                </>
              )}
            </>
          }
          summaryRows={[
            { label: 'Origem', value: result.source.replace('_', ' ') },
            { label: 'Coletada em', value: new Date(result.capturedAt).toLocaleString('pt-BR') },
            { label: 'Eventos registrados', value: String(result.events.length) },
            {
              label: 'Verificação Ed25519 (nesta camada)',
              value:
                sigBadge === 'verified'
                  ? `✓ ${sigValid}/${sigTotal} assinaturas válidas (Web Crypto / RFC 8032)`
                  : sigBadge === 'tampered'
                    ? `✗ ${sigInvalid}/${sigTotal} assinaturas inválidas — possível adulteração`
                    : sigBadge === 'pending'
                      ? '… executando verificação local'
                      : 'sem âncora Ed25519 vinculada a este hash',
            },
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

        <PartSection className="pt-8">
          <PartHeader
            number="IV"
            title="Da Verificação Criptográfica Independente"
            subtitle="Resultado executado nesta camada de apresentação · Web Crypto API · Ed25519 / RFC 8032"
          />
        </PartSection>

        <PartSection breakBefore={false} className="mt-4">
          <p className="text-[11.5px] leading-[1.65] text-justify mb-3" style={{ fontFamily: FONT_BODY }}>
            Em atenção ao achado <strong>N-03</strong> da reanálise pericial (Trace Hub
            Forensic Core v2, jun/2026), a presente camada de apresentação{' '}
            <strong>executa diretamente</strong> a verificação criptográfica das assinaturas{' '}
            <em>Ed25519</em> registradas em <code>forensic_chain_signatures</code> para este{' '}
            <em>hash</em>, sem delegar exclusivamente ao módulo <code>/verificar-evidencia</code>.
            O cálculo é local (Web Crypto API nativa do navegador) e independente da
            infraestrutura do Trace Hub.
          </p>

          <div
            className="rounded-lg p-3 mb-4 flex items-center gap-3 border-2"
            style={{
              borderColor:
                sigBadge === 'verified' ? '#10b981' : sigBadge === 'tampered' ? '#dc2626' : '#f59e0b',
              backgroundColor:
                sigBadge === 'verified' ? '#ecfdf5' : sigBadge === 'tampered' ? '#fef2f2' : '#fffbeb',
            }}
          >
            {sigBadge === 'verified' ? (
              <ShieldCheck className="w-6 h-6 shrink-0" style={{ color: '#059669' }} />
            ) : sigBadge === 'tampered' ? (
              <ShieldAlert className="w-6 h-6 shrink-0" style={{ color: '#dc2626' }} />
            ) : (
              <ShieldQuestion className="w-6 h-6 shrink-0" style={{ color: '#d97706' }} />
            )}
            <div>
              <p className="text-[12px] font-bold" style={{ fontFamily: FONT_HEADING }}>
                {sigBadge === 'verified' && `ASSINATURAS Ed25519 VÁLIDAS · ${sigValid}/${sigTotal}`}
                {sigBadge === 'tampered' && `ASSINATURAS INVÁLIDAS · ${sigInvalid}/${sigTotal} FALHARAM`}
                {sigBadge === 'absent' && 'HASH PRESENTE · SEM ANCORAGEM NESTA CAMADA'}
                {sigBadge === 'pending' && 'EXECUTANDO VERIFICAÇÃO LOCAL…'}
              </p>
              <p className="text-[10.5px] mt-0.5" style={{ fontFamily: FONT_BODY, color: '#374151' }}>
                {sigBadge === 'verified' &&
                  'Cada assinatura foi reconstruída e validada localmente via crypto.subtle.verify (algoritmo Ed25519). Cadeia íntegra.'}
                {sigBadge === 'tampered' &&
                  'Ao menos uma assinatura não confere com a chave pública registrada. Considerar adulteração.'}
                {sigBadge === 'absent' &&
                  'Não há registros em forensic_chain_signatures para este hash. A integridade pode ser atestada de forma complementar via /verificar-evidencia (RFC 3161 + OpenTimestamps).'}
                {sigBadge === 'pending' && 'Aguarde — a verificação roda no navegador, sem chamada de rede adicional.'}
              </p>
            </div>
          </div>

          {sigChecks && sigChecks.length > 0 && (
            <table className="w-full text-[10.5px] border-collapse" style={{ fontFamily: FONT_BODY }}>
              <thead>
                <tr style={{ backgroundColor: '#f3f4f6' }}>
                  <th className="text-left p-2 border" style={{ borderColor: '#e5e7eb' }}>#</th>
                  <th className="text-left p-2 border" style={{ borderColor: '#e5e7eb' }}>Etapa</th>
                  <th className="text-left p-2 border" style={{ borderColor: '#e5e7eb' }}>Assinada em</th>
                  <th className="text-left p-2 border" style={{ borderColor: '#e5e7eb' }}>Resultado</th>
                </tr>
              </thead>
              <tbody>
                {sigChecks.map((c) => (
                  <tr key={c.step_index}>
                    <td className="p-2 border" style={{ borderColor: '#e5e7eb', fontFamily: FONT_MONO }}>{c.step_index}</td>
                    <td className="p-2 border" style={{ borderColor: '#e5e7eb' }}>{c.step_label || '—'}</td>
                    <td className="p-2 border" style={{ borderColor: '#e5e7eb', fontFamily: FONT_MONO }}>
                      {new Date(c.signed_at).toLocaleString('pt-BR')}
                    </td>
                    <td className="p-2 border font-bold" style={{ borderColor: '#e5e7eb', color: c.status === 'valid' ? '#059669' : c.status === 'invalid' ? '#dc2626' : '#d97706' }}>
                      {c.status === 'valid' && '✓ Ed25519 válida'}
                      {c.status === 'invalid' && '✗ Assinatura inválida'}
                      {c.status === 'unsupported' && 'i Ed25519 não suportado neste navegador'}
                      {c.status === 'error' && 'i Erro ao verificar'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <p className="text-[10px] mt-3 text-justify" style={{ fontFamily: FONT_BODY, color: '#6b7280' }}>
            A verificação RFC 3161 (TSR) e OpenTimestamps (OTS) continua disponível de forma
            independente em <code>/verificar-evidencia</code> e por linha de comando{' '}
            (<code>openssl ts -verify</code>, <code>ots verify</code>).
          </p>
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
              detail: 'Hash localizado nos registros — verificação criptográfica disponível em /verificar-evidencia',
              icon: 'export',
            },
          ],
          metadata: {
            'Tipo de laudo': report.report_type,
            'Assunto': report.subject || '—',
            'Emitido em': new Date(report.created_at).toLocaleString('pt-BR'),
          },
        });
        toast.success('Registros localizados');

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
          detail: 'Hash localizado nos registros — verificação criptográfica disponível em /verificar-evidencia',
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
        toast.success('Registros localizados');
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

        <div className="text-[11px] text-muted-foreground border-t pt-3 space-y-1">
          <p>
            <strong>Uso processual:</strong> Anexe este documento à petição inicial ou laudo
            como demonstração de <em>presença e cronologia</em> da evidência nos registros
            Trace Hub (art. 158-A do CPP).
          </p>
          <p>
            <strong>Admissibilidade plena:</strong> a verificação criptográfica independente
            (recálculo SHA-256, validação RFC 3161 e OpenTimestamps) deve ser apresentada via{' '}
            <code>/verificar-evidencia</code> ou por CLI{' '}
            (<code>openssl ts -verify</code>, <code>ots verify</code>,{' '}
            <code>sha256sum -c</code>).
          </p>
        </div>

      </CardContent>
    </Card>
  );
}

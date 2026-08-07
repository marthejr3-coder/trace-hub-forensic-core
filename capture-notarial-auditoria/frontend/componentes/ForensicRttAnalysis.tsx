import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Satellite, Info, AlertTriangle, CheckCircle2, HelpCircle } from 'lucide-react';
import { analyzeForensicRtt, type RttProbe } from '@/lib/forensic-rtt-analysis';

interface Props {
  probes: RttProbe[];
  networkType?: string | null;
  effectiveType?: string | null;
  ipCity?: string | null;
  ipRegion?: string | null;
  ipCountry?: string | null;
  ipLat?: number | null;
  ipLon?: number | null;
}

export default function ForensicRttAnalysis({
  probes,
  networkType,
  effectiveType,
  ipCity,
  ipRegion,
  ipCountry,
  ipLat,
  ipLon,
}: Props) {
  const result = analyzeForensicRtt({
    probes,
    network_type: networkType,
    effective_type: effectiveType,
    ip_city: ipCity,
    ip_region: ipRegion,
    ip_country: ipCountry,
    ip_lat: ipLat,
    ip_lon: ipLon,
  });

  if (!result) return null;

  const consistencyVariant: 'default' | 'destructive' | 'secondary' =
    result.consistency.flag === 'consistent'
      ? 'default'
      : result.consistency.suspected_vpn_or_proxy
      ? 'destructive'
      : 'secondary';

  const confidenceLabel =
    result.confidence === 'high'
      ? 'Alta'
      : result.confidence === 'medium'
      ? 'Média'
      : 'Baixa';

  return (
    <Card className="border-primary/20">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Satellite className="h-5 w-5 text-primary" />
          Análise Forense de Rede — Gateway Geocalizado
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <button type="button" className="text-muted-foreground hover:text-foreground">
                  <Info className="h-3.5 w-3.5" />
                </button>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">
                <p className="text-xs leading-relaxed">
                  Estimativa baseada na <strong>velocidade da luz na fibra óptica</strong> ({result.fiber_speed_km_per_ms} km/ms),
                  com fator <strong>{result.routing_overhead_factor}</strong> para overhead de roteamento real.
                  <br />
                  <br />
                  Fórmula: <code>{result.formula}</code>
                </p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {/* Raio estimado em destaque */}
        <div className="rounded-lg border bg-muted/30 p-3 flex items-baseline justify-between">
          <span className="text-muted-foreground text-xs uppercase tracking-wide">Raio estimado</span>
          <span className="text-2xl font-bold text-primary">~{result.estimated_radius_km} km</span>
        </div>

        {/* Faixa interpretativa */}
        <div className="flex items-center justify-between gap-2 text-xs">
          <span className="text-muted-foreground">Faixa</span>
          <span className="font-medium text-right">
            {result.band_label} <span className="text-muted-foreground">({result.band_range_km})</span>
          </span>
        </div>

        {/* RTT detalhado */}
        <div className="space-y-1.5 border-t pt-3">
          <div className="flex justify-between text-xs">
            <span className="text-muted-foreground">RTT efetivo</span>
            <span className="font-mono font-medium">
              {result.effective_rtt_ms} ms
              {result.noise_subtracted_ms > 0 && (
                <span className="text-muted-foreground ml-1">(bruto: {result.raw_rtt_ms} ms)</span>
              )}
            </span>
          </div>
          {result.noise_subtracted_ms > 0 && (
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">Limpeza de ruído</span>
              <span className="font-mono text-muted-foreground">
                −{result.noise_subtracted_ms} ms <span className="opacity-70">(rede móvel)</span>
              </span>
            </div>
          )}
          <div className="flex justify-between text-xs">
            <span className="text-muted-foreground">Servidor mais próximo</span>
            <span className="font-medium text-right">{result.nearest_probe.target}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="text-muted-foreground">Região do servidor</span>
            <span className="text-right text-muted-foreground">{result.nearest_probe.region}</span>
          </div>
        </div>

        {/* Consistência IP */}
        <div className="border-t pt-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">📍 IP geolocalizado</span>
            <span className="font-medium">
              {ipCity || '—'}{ipRegion ? `/${ipRegion}` : ''}
            </span>
          </div>
          {result.consistency.distance_to_ip_km !== null && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Distância IP ↔ servidor</span>
              <span className="font-mono">{result.consistency.distance_to_ip_km} km</span>
            </div>
          )}
          <Badge variant={consistencyVariant} className="w-full justify-start gap-1.5 py-1.5">
            {result.consistency.flag === 'consistent' && <CheckCircle2 className="h-3.5 w-3.5" />}
            {result.consistency.suspected_vpn_or_proxy && <AlertTriangle className="h-3.5 w-3.5" />}
            {result.consistency.flag === 'unknown' && <HelpCircle className="h-3.5 w-3.5" />}
            <span className="text-xs font-normal leading-snug whitespace-normal text-left">
              {result.consistency.reason}
            </span>
          </Badge>
        </div>

        {/* Veredito final */}
        <div className="border-t pt-3">
          <div className="text-xs uppercase tracking-wide text-muted-foreground mb-1">Veredito</div>
          <p className="text-sm leading-relaxed">{result.verdict}</p>
        </div>

        {/* Rodapé técnico */}
        <div className="border-t pt-2 flex items-center justify-between text-[10px] text-muted-foreground">
          <span>
            Confiança: <strong className="text-foreground">{confidenceLabel}</strong> · {probes.length} probes
          </span>
          <span className="font-mono">
            {result.fiber_speed_km_per_ms} km/ms · ×{result.routing_overhead_factor}
          </span>
        </div>
        <p className="text-[10px] text-muted-foreground italic leading-snug">
          Estimativa determinística baseada em velocidade da luz no vidro com fator de overhead de roteamento.
          Não substitui geolocalização GPS nem ordem judicial para identificação precisa.
        </p>
      </CardContent>
    </Card>
  );
}

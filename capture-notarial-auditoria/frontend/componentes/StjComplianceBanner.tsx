import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ShieldCheck, AlertTriangle } from 'lucide-react';

interface Props {
  /**
   * `collection` — ferramenta gera prova primária. Mostra alerta CPP 158-A +
   * referência ao STJ AgRg HC 943.895/PR (proibição de acesso pré-perícia).
   * `analysis` — ferramenta apenas analisa material já coletado. Badge informativo.
   */
  variant: 'collection' | 'analysis';
  /** Opcional: substitui o texto-padrão. */
  customMessage?: string;
}

/**
 * Banner de conformidade STJ — exibido no topo das ferramentas forenses
 * para deixar explícito ao operador o limite jurídico de uso.
 * Atende: CPP art. 158-A a 158-F (Lei 13.964/19) + jurisprudência STJ 2025.
 */
export function StjComplianceBanner({ variant, customMessage }: Props) {
  if (variant === 'collection') {
    return (
      <Alert className="border-amber-500/40 bg-amber-500/10 text-amber-900 dark:text-amber-200">
        <AlertTriangle className="w-4 h-4" />
        <AlertTitle className="text-sm font-semibold">
          Uso restrito — Cadeia de Custódia CPP art. 158-A
        </AlertTitle>
        <AlertDescription className="text-xs mt-1 space-y-1">
          <p>
            {customMessage ??
              'Esta ferramenta gera prova digital primária com hash SHA-256, metadados e selo temporal independente. Use somente em fonte aberta, com consentimento da vítima/titular, ou sob ordem judicial.'}
          </p>
          <p className="italic opacity-90">
            Não substitui perícia oficial em dispositivo apreendido. Acesso prévio à perícia
            quebra a cadeia (STJ · AgRg HC 943.895/PR · 5ª Turma · 2025).
          </p>
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <Alert className="border-border bg-muted/40">
      <ShieldCheck className="w-4 h-4 text-muted-foreground" />
      <AlertDescription className="text-xs text-muted-foreground">
        {customMessage ??
          'Ferramenta de análise técnica de material já coletado. Não constitui coleta primária de prova — utilize Ata Notarial Digital ou Validação WhatsApp para gerar evidência com cadeia de custódia completa.'}
      </AlertDescription>
    </Alert>
  );
}

export default StjComplianceBanner;

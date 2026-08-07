import { useState, useEffect } from 'react';
import { Shield, Copy, Check } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { generateEvidenceHash, formatHashForDisplay } from '@/lib/forensic-hash';
import { toast } from 'sonner';

interface ForensicBadgeProps {
  evidence: Record<string, any>;
  compact?: boolean;
}

export default function ForensicBadge({ evidence, compact = false }: ForensicBadgeProps) {
  const [hash, setHash] = useState<string | null>(null);
  const [timestamp, setTimestamp] = useState<string>('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    generateEvidenceHash(evidence).then(result => {
      setHash(result.hash);
      setTimestamp(result.timestamp);
    });
  }, [evidence]);

  const handleCopy = () => {
    if (!hash) return;
    const text = `SHA-256: ${hash}\nTimestamp: ${timestamp}\nAlgorithm: SHA-256`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success('Hash forense copiado!');
    setTimeout(() => setCopied(false), 2000);
  };

  if (!hash) return null;

  if (compact) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge 
            variant="outline" 
            className="cursor-pointer gap-1 text-[10px] font-mono border-emerald-500/30 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/10"
            onClick={handleCopy}
          >
            <Shield className="h-3 w-3" />
            {hash.slice(0, 8)}…
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          <p className="font-mono text-[10px] break-all">SHA-256: {formatHashForDisplay(hash)}</p>
          <p className="text-[10px] text-muted-foreground mt-1">{timestamp}</p>
          <p className="text-[10px] text-emerald-500 mt-1">✓ Evidência com integridade verificável</p>
        </TooltipContent>
      </Tooltip>
    );
  }

  return (
    <div className="flex items-center gap-2 p-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
      <Shield className="h-4 w-4 text-emerald-500 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-[10px] font-medium text-emerald-600 dark:text-emerald-400">Certificado Forense SHA-256</p>
        <p className="text-[9px] font-mono text-muted-foreground truncate">{hash}</p>
      </div>
      <button onClick={handleCopy} className="p-1 hover:bg-emerald-500/10 rounded transition-colors">
        {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3 text-muted-foreground" />}
      </button>
    </div>
  );
}

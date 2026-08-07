import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { GitCompareArrows, Fingerprint } from 'lucide-react';
import CaseComparator from '@/components/CaseComparator';
import FingerprintCorrelation from '@/components/FingerprintCorrelation';

export default function ForensicAnalysis() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-1.5 h-8 bg-primary rounded-full" />
        <h3 className="text-xl font-black text-foreground tracking-tight">Análise Forense</h3>
      </div>

      <Tabs defaultValue="compare" className="space-y-4">
        <TabsList className="bg-muted/30 rounded-xl p-1.5 border border-border/40 gap-2">
          <TabsTrigger value="compare" className="rounded-lg font-black text-sm gap-2 px-4 py-2.5 data-[state=active]:bg-cyan-600 data-[state=active]:text-white">
            <GitCompareArrows className="w-4 h-4" />
            Comparar Casos
          </TabsTrigger>
          <TabsTrigger value="correlate" className="rounded-lg font-black text-sm gap-2 px-4 py-2.5 data-[state=active]:bg-amber-600 data-[state=active]:text-white">
            <Fingerprint className="w-4 h-4" />
            Correlação Digital
          </TabsTrigger>
        </TabsList>

        <TabsContent value="compare">
          <CaseComparator />
        </TabsContent>

        <TabsContent value="correlate">
          <FingerprintCorrelation />
        </TabsContent>
      </Tabs>
    </div>
  );
}

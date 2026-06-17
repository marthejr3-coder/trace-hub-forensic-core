import { Helmet } from 'react-helmet-async';
import { Link } from 'react-router-dom';
import { Shield, GitBranch, Server, Anchor, ArrowLeft, ExternalLink } from 'lucide-react';
import { Button } from '@/components/ui/button';

const Section = ({ icon: Icon, title, children }: { icon: React.ElementType; title: string; children: React.ReactNode }) => (
  <section className="rounded-2xl border border-border bg-card p-6 sm:p-8 space-y-4">
    <div className="flex items-center gap-3">
      <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
        <Icon className="w-5 h-5 text-primary" />
      </div>
      <h2 className="text-lg sm:text-xl font-bold text-foreground">{title}</h2>
    </div>
    {children}
  </section>
);

const Code = ({ children }: { children: React.ReactNode }) => (
  <pre className="bg-muted rounded-lg p-4 text-xs sm:text-sm font-mono text-muted-foreground overflow-x-auto whitespace-pre leading-relaxed">
    {children}
  </pre>
);

export default function AuditoriaPublica() {
  return (
    <>
      <Helmet>
        <title>Auditoria Pública — Trace Hub</title>
        <meta name="description" content="Transparência técnica do Trace Hub: código-fonte auditável, arquitetura de captura, ambiente sandbox e ancoragem criptográfica redundante." />
      </Helmet>

      <div className="min-h-screen bg-background text-foreground">
        <header className="border-b border-border bg-card/80 backdrop-blur sticky top-0 z-30">
          <div className="max-w-4xl mx-auto flex items-center gap-3 px-4 py-4">
            <Link to="/">
              <Button variant="ghost" size="icon" aria-label="Voltar">
                <ArrowLeft className="w-5 h-5" />
              </Button>
            </Link>
            <div>
              <h1 className="text-lg font-bold">Auditoria Pública</h1>
              <p className="text-xs text-muted-foreground">Transparência técnica do Trace Hub</p>
            </div>
          </div>
        </header>

        <main className="max-w-4xl mx-auto px-4 py-10 space-y-8">

          {/* 1 — Código-fonte auditável */}
          <Section icon={GitBranch} title="Código-fonte auditável">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Os módulos críticos de captura, hashing e ancoragem são publicados em repositório aberto
              para auditoria independente. Qualquer perito, advogado ou juiz pode inspecionar a lógica
              que gera e protege as evidências.
            </p>
            <a
              href="https://github.com/marthejr3-coder/trace-hub-forensic-core"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-sm text-primary hover:underline"
            >
              <ExternalLink className="w-4 h-4" />
              github.com/marthejr3-coder/trace-hub-forensic-core
            </a>
            <div className="space-y-1">
              <p className="text-xs font-semibold text-foreground uppercase tracking-wider">Módulos abertos</p>
              <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                <li><code className="text-xs">forensic-hash.ts</code> — SHA-256 via Web Crypto (evidence_hash)</li>
                <li><code className="text-xs">tsr-verify.ts</code> — Verificação RFC 3161 (TSR)</li>
                <li><code className="text-xs">ots-verify.ts</code> — Verificação OpenTimestamps (Bitcoin)</li>
                <li><code className="text-xs">pades-stamp.ts</code> — Carimbo PAdES em PDF</li>
                <li><code className="text-xs">originstamp-anchor</code> — Edge Function de ancoragem multi-chain</li>
                <li><code className="text-xs">evidence-integrity-probe</code> — Edge Function de prova de integridade</li>
                {/* notarial-capture: módulo proprietário — não publicado no repositório aberto. Removido desta lista para evitar declaração não verificável (achado N-05 da reanálise pericial). */}
                <li><code className="text-xs">sealed-session-event</code> / <code className="text-xs">sealed-session-finalize</code> — Selagem SHA-256 da sessão</li>
              </ul>
            </div>
            <p className="text-xs text-muted-foreground">
              Licença: <a href="/LICENSE-forensic-core.txt" className="underline hover:text-primary">BUSL 1.1</a> →
              Apache 2.0 após 4 anos. Veja o <a href="/MANIFEST-forensic-core.md" className="underline hover:text-primary">MANIFEST</a> completo.
            </p>
          </Section>

          {/* 2 — Arquitetura de separação */}
          <Section icon={Server} title="Arquitetura de captura e armazenamento">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Cada etapa da cadeia de custódia roda em domínio e credencial distintos, impedindo que
              uma única parte comprometa a evidência.
            </p>
            <Code>{`
┌──────────────┐     HTTPS      ┌────────────────────────┐
│  Cliente     │ ──────────────▸│  Edge Function          │
│  (navegador) │                │  notarial-capture        │
└──────────────┘                │  ┌────────────────────┐ │
                                │  │ Chromium headless   │ │
                                │  │ sandbox isolado     │ │
                                │  └────────┬───────────┘ │
                                └───────────┼─────────────┘
                                            │
                           ┌────────────────┼────────────────┐
                           │                │                │
                           ▼                ▼                ▼
                  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐
                  │  Storage    │  │  Database     │  │  Ancoragem  │
                  │  write-once │  │  RLS strict   │  │  externa    │
                  │  (bucket)   │  │  evidence_hash│  │             │
                  └─────────────┘  └──────────────┘  │ • OTS (BTC) │
                                                     │ • FreeTSA   │
                                                     │ • DigiCert  │
                                                     │ • OriginSt. │
                                                     └─────────────┘
            `.trim()}</Code>
          </Section>

          {/* 3 — Ambiente de captura sandbox */}
          <Section icon={Shield} title="Ambiente de captura sandbox">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Cada captura ocorre em um ambiente Chromium isolado, sem contaminação de sessão.
              Abaixo a declaração formal do ambiente:
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              {[
                ['Motor de renderização', 'Chromium headless (última versão estável)'],
                ['Extensões do navegador', 'Nenhuma — desabilitadas no sandbox'],
                ['Cache HTTP', 'Zerado a cada sessão de captura'],
                ['Cookies / localStorage', 'Vazios — sem cookies prévios'],
                ['User-Agent', 'Declarado no laudo (string completa)'],
                ['IP de origem', 'Datacenter (registrado no laudo)'],
                ['DNS', 'Resolução independente — Google + Cloudflare'],
                ['Certificados TLS', 'Validação padrão — sem override de CA'],
              ].map(([k, v]) => (
                <div key={k} className="rounded-lg border border-border p-3">
                  <p className="text-xs text-muted-foreground">{k}</p>
                  <p className="font-medium text-foreground text-sm">{v}</p>
                </div>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              Esse ambiente é equivalente ao "modo anônimo" forense descrito na literatura de
              perícia digital (Cellebrite UFED, Axiom, etc.), garantindo que o conteúdo capturado
              reflete fielmente o que qualquer visitante veria.
            </p>
          </Section>

          {/* 4 — Ancoragem redundante */}
          <Section icon={Anchor} title="Ancoragem criptográfica redundante">
            <p className="text-sm text-muted-foreground leading-relaxed">
              O hash SHA-256 de cada evidência é ancorado em múltiplos registros imutáveis e
              independentes. Se qualquer um deles for questionado, os demais servem de
              contra-prova.
            </p>
            <div className="space-y-3">
              {[
                { name: 'Bitcoin (OpenTimestamps)', status: 'Ativo', desc: 'Carimbo na blockchain Bitcoin — imutabilidade máxima, confirmação em ~1h.' },
                { name: 'RFC 3161 — FreeTSA', status: 'Ativo', desc: 'Carimbo de tempo TSA gratuito — resposta em segundos, padrão IETF.' },
                { name: 'RFC 3161 — DigiCert', status: 'Ativo', desc: 'Carimbo de tempo de CA comercial — aceito globalmente em processos judiciais.' },
                { name: 'OriginStamp (BTC + ETH + IPFS)', status: 'Ativo', desc: 'Ancoragem multi-chain via API OriginStamp v4 — redundância adicional.' },
                { name: 'Ethereum (roadmap)', status: 'Planejado', desc: 'Smart contract dedicado para prova de existência — em desenvolvimento.' },
                { name: 'IPFS (roadmap)', status: 'Planejado', desc: 'Armazenamento distribuído do hash — imutabilidade por content-addressing.' },
              ].map(a => (
                <div key={a.name} className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <span className={`mt-0.5 text-xs font-bold px-2 py-0.5 rounded-full ${a.status === 'Ativo' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-muted text-muted-foreground'}`}>
                    {a.status}
                  </span>
                  <div>
                    <p className="text-sm font-semibold text-foreground">{a.name}</p>
                    <p className="text-xs text-muted-foreground">{a.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </Section>

          <div className="text-center pt-4">
            <Link to="/verificar-evidencia">
              <Button variant="outline">Verificar uma evidência →</Button>
            </Link>
          </div>
        </main>

        <footer className="border-t border-border py-6 text-center text-xs text-muted-foreground">
          © {new Date().getFullYear()} Trace Hub — Transparência técnica para admissibilidade judicial.
        </footer>
      </div>
    </>
  );
}

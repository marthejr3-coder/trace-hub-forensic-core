# Trace Hub — Forensic Core: Manifesto Público

Este documento lista exatamente os arquivos do código-fonte do Trace Hub que
serão publicados no repositório aberto **marthejr3-coder/trace-hub-forensic-core** para
auditoria independente por peritos, advogados, juízes e a comunidade técnica.

A publicação obedece à licença [BUSL 1.1](./LICENSE-forensic-core.txt) com
*Change Date* de 4 anos e *Change License* Apache 2.0.

## Escopo

São publicados **apenas** os módulos críticos de:

- Cálculo e verificação de hashes forenses
- Verificação de carimbos de tempo (RFC 3161 e OpenTimestamps)
- Carimbo PAdES em PDF
- Edge Functions de captura selada e ancoragem
- Esquema de banco relevante para integridade (RLS + tabelas selladas)

**Não** são publicados: lógica de billing, integrações com Mercado Pago,
templates de captura, fingerprinting passivo, chaves, secrets, dashboards
internos, regras de detecção CSAM, painel admin, ou qualquer dado de cliente.

## Arquivos publicados

### Hashing e verificação criptográfica
- `src/lib/forensic-hash.ts` — SHA-256 via Web Crypto (gera `evidence_hash`)
- `src/lib/tsr-verify.ts` — Verificação RFC 3161 (carimbo de tempo)
- `src/lib/ots-verify.ts` — Verificação OpenTimestamps (Bitcoin)
- `src/lib/pades-stamp.ts` — Aplicação de carimbo PAdES em PDF
- `src/lib/whatsapp-audio-validator.ts` — Validador determinístico Opus/OGG

### Edge Functions (Deno)
- `supabase/functions/notarial-capture/index.ts` — Captura notarial em Chromium sandbox (headless)
- `supabase/functions/sealed-session-event/index.ts` — Append-only de eventos da sessão selada
- `supabase/functions/sealed-session-finalize/index.ts` — Finalização e selagem SHA-256 da sessão
- `supabase/functions/sealed-proxy/index.ts` — Proxy reverso para captura selada
- `supabase/functions/originstamp-anchor/index.ts` — Ancoragem multi-chain
- `supabase/functions/originstamp-verify/index.ts` — Verificação de ancoragem
- `supabase/functions/evidence-integrity-probe/index.ts` — Prova de integridade DNS/TLS
- `supabase/functions/verify-evidence-hash/index.ts` — Verificação pública de hash de evidência

### Esquema de banco (somente DDL relevante à integridade)
- `sealed_capture_events` (estrutura + RLS deny-all em writes do cliente)
- `capture_link_sessions` (estrutura + RPC `get_capture_session_by_token`)
- `evidence_vault` (bucket privado + política scoped por operator_id)

### Verificadores públicos
- `src/pages/VerificarEvidenciaPublica.tsx` — Página pública de verificação
- `src/pages/AuditoriaPublica.tsx` — Esta página de transparência
- `public/LICENSE-forensic-core.txt` — Licença BUSL 1.1
- `public/MANIFEST-forensic-core.md` — Este arquivo

## O que NÃO é publicado

Para evitar abuso e proteger usuários, **não** publicamos:

- Templates de captura (Instagram, Google, Uber, iFood, etc.)
- Lógica de cloaking e bridge pages
- Painel admin (`/admin`, `/intrusive-mode`)
- Triagem CSAM (regras de hash, keywords leet, ensemble perceptual)
- Integrações de pagamento (Mercado Pago)
- Notificações Telegram/Push
- Geolocalização ativa (consent flow, ConsentCapturePage)
- Fingerprinting passivo e Anti-Spy

Isso preserva a verossimilhança operacional e evita que cópias do produto
sejam usadas contra vítimas de golpes.

## Como auditar

1. Clone o repositório:
   `git clone https://github.com/marthejr3-coder/trace-hub-forensic-core.git`
2. Inspecione qualquer módulo da lista acima.
3. Reporte vulnerabilidades em `security@trace-hub.com` (PGP disponível).
4. Para auditoria formal com NDA estendido, contate
   `auditoria@trace-hub.com`.

## Versionamento

Cada release do `forensic-core` é assinada com hash SHA-256 e ancorada em
Bitcoin via OpenTimestamps. Veja a tag do release no GitHub para o
`.ots` correspondente.

---

**Trace Hub Tec Inova Simples (I.S.)** — CNPJ 67.302.275/0001-50

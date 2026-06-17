# Trace Hub — Arquivos modificados nesta sessão

Aplique sobre a raiz do repositório (mesmos caminhos relativos).

## Frontend
- src/components/juridico/CadeiaCustodia.tsx
- src/components/csam/CSAMSecondaryAttestationCard.tsx
- src/hooks/useSealedSession.ts  (proxy via token opaco — F-02)
- src/lib/pdf-self-hash.ts        (novo — sidecar .sha256.txt)
- src/lib/resumo-juizo-pdf.ts     (novo — "Resumo para o Juízo")
- src/lib/custody-laudo-pdf.ts
- src/lib/pdf-multipage.ts
- src/pages/VerificarEvidenciaPublica.tsx
- src/pages/AuditoriaPublica.tsx

## Edge Functions
- supabase/functions/verify-evidence-hash/index.ts
- supabase/functions/sealed-proxy/index.ts          (aceita ?t=<opaco>)
- supabase/functions/sealed-proxy-token/index.ts    (novo — token efêmero)
- supabase/functions/csam-secondary-signoff/index.ts(novo — anti self-attestation)

## Migrations
- supabase/migrations/20260617015309_*.sql  (evidence_vault_seal + triggers)
- supabase/migrations/20260617114356_*.sql  (sealed_proxy_tokens + RLS RESTRICTIVE)

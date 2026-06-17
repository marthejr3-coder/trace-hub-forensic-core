
CREATE TABLE IF NOT EXISTS public.sealed_proxy_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash TEXT NOT NULL UNIQUE,
  session_id UUID NOT NULL,
  user_id UUID NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT ALL ON public.sealed_proxy_tokens TO service_role;
ALTER TABLE public.sealed_proxy_tokens ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_sealed_proxy_tokens_expires
  ON public.sealed_proxy_tokens (expires_at);

-- Bloqueia auto-atestação ICAC (N-01).
DROP POLICY IF EXISTS "No self attestation" ON public.csam_session_signoffs;

CREATE POLICY "No self attestation"
ON public.csam_session_signoffs
AS RESTRICTIVE
FOR INSERT
TO authenticated
WITH CHECK (
  primary_operator_id IS NULL
  OR secondary_operator_id <> primary_operator_id
);


-- Selo de imutabilidade do Evidence Vault (append-only).
-- Cada blob persistido no bucket evidence_vault recebe uma linha aqui no momento
-- em que verify-evidence-hash é executado. UPDATE/DELETE são bloqueados por trigger,
-- de modo que qualquer alteração futura do arquivo no storage é detectável.

CREATE TABLE public.evidence_vault_seal (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  evidence_id UUID NOT NULL UNIQUE REFERENCES public.capture_link_evidence(id) ON DELETE RESTRICT,
  file_path TEXT NOT NULL,
  hash_client TEXT NOT NULL,
  hash_server TEXT NOT NULL,
  hash_server_sha512 TEXT,
  file_size BIGINT,
  sealed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sealed_by TEXT NOT NULL DEFAULT 'verify-evidence-hash'
);

GRANT SELECT ON public.evidence_vault_seal TO authenticated;
GRANT SELECT ON public.evidence_vault_seal TO anon;
GRANT ALL ON public.evidence_vault_seal TO service_role;

ALTER TABLE public.evidence_vault_seal ENABLE ROW LEVEL SECURITY;

-- Leitura pública: o seal só guarda hash + caminho (sem PII), e a verificação
-- precisa ser auditável por qualquer operador do direito.
CREATE POLICY "Public can read seals"
  ON public.evidence_vault_seal
  FOR SELECT
  USING (true);

-- Bloqueio absoluto de UPDATE/DELETE (mesmo via service_role só passa removendo este trigger).
CREATE OR REPLACE FUNCTION public.evidence_vault_seal_block_mutations()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  RAISE EXCEPTION 'evidence_vault_seal é append-only: % bloqueado para preservar cadeia de custódia (CPP art. 158-B)', TG_OP;
END;
$$;

CREATE TRIGGER evidence_vault_seal_no_update
  BEFORE UPDATE ON public.evidence_vault_seal
  FOR EACH ROW EXECUTE FUNCTION public.evidence_vault_seal_block_mutations();

CREATE TRIGGER evidence_vault_seal_no_delete
  BEFORE DELETE ON public.evidence_vault_seal
  FOR EACH ROW EXECUTE FUNCTION public.evidence_vault_seal_block_mutations();

CREATE INDEX idx_evidence_vault_seal_sealed_at ON public.evidence_vault_seal(sealed_at DESC);

COMMENT ON TABLE public.evidence_vault_seal IS
  'Selo append-only de cada arquivo persistido no bucket evidence_vault. UPDATE/DELETE bloqueados por trigger. Preenchido por verify-evidence-hash uma única vez por evidência.';

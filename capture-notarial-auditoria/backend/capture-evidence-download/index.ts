// Cofre 72h - gera signed URLs para a parte baixar evidências capturadas.
// Valida o token público da sessão (mesmo usado em /capture-link) e devolve
// um link temporário pro arquivo no bucket privado evidence_vault. Carimba
// downloaded_at na primeira chamada (auditoria).
import { createClient } from "npm:@supabase/supabase-js@2.57.2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { token, evidence_id } = await req.json();
    if (!token || !evidence_id) {
      return json({ error: "token e evidence_id são obrigatórios" }, 400);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    const { data: rows, error } = await supabase.rpc("get_capture_evidence_file_path", {
      p_token: token,
      p_evidence_id: evidence_id,
    });

    if (error) {
      console.error("[capture-evidence-download] rpc error", error);
      return json({ error: "Falha ao validar token" }, 500);
    }

    const row = Array.isArray(rows) ? rows[0] : rows;
    if (!row) {
      return json({
        error: "Esta evidência expirou (política de retenção de 72h) e não pode mais ser baixada. Peça à vítima que envie novamente pelo link de captura.",
        code: "expired",
      }, 410);
    }

    // Verifica se o objeto ainda existe no bucket antes de gerar signed URL.
    // Storage do Supabase responde "Object not found" no download se o arquivo
    // já foi removido pela rotina de retenção 72h — devolvemos mensagem clara.
    try {
      const parts = (row.file_path as string).split("/");
      const basename = parts.pop()!;
      const folder = parts.join("/");
      const { data: listed } = await supabase.storage
        .from("evidence_vault")
        .list(folder, { search: basename, limit: 1 });
      const exists = listed?.some((o: any) => o.name === basename);
      if (!exists) {
        const receivedAt = row.received_at_server ? new Date(row.received_at_server as string).getTime() : 0;
        const ageMs = Date.now() - receivedAt;
        if (receivedAt > 0 && ageMs > 72 * 60 * 60 * 1000) {
          return json({
            error: "Esta evidência expirou (política de retenção de 72h) e foi removida do cofre. Peça à vítima que envie novamente pelo link de captura.",
            code: "expired",
          }, 410);
        }
        return json({
          error: "Arquivo indisponível temporariamente. Tente novamente em alguns minutos.",
          code: "object_missing",
        }, 404);
      }
    } catch (e) {
      console.warn("[capture-evidence-download] storage list check failed", e);
    }

    const { data: signed, error: signErr } = await supabase
      .storage
      .from("evidence_vault")
      .createSignedUrl(row.file_path, 60 * 60); // 1h

    if (signErr || !signed?.signedUrl) {
      console.error("[capture-evidence-download] sign error", signErr);
      return json({ error: "Falha ao gerar link de download" }, 500);
    }

    // Best-effort: carimba downloaded_at + incrementa contador
    supabase.rpc("mark_capture_evidence_downloaded", { p_evidence_id: row.id })
      .then(({ error }) => {
        if (error) console.warn("[capture-evidence-download] mark error", error);
      });

    return json({
      signed_url: signed.signedUrl,
      file_name: row.file_name,
      mime_type: row.mime_type,
      file_size: row.file_size,
      hash_sha256: row.hash_client,
      expires_at_seconds: 3600,
    });
  } catch (e) {
    console.error("[capture-evidence-download] fatal", e);
    return json({ error: e instanceof Error ? e.message : "Erro desconhecido" }, 500);
  }
});

function json(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

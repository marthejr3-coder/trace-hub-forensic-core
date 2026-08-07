// Apaga arquivos do bucket `evidence_vault` e seus registros em
// `capture_link_evidence` após 72h da captura. Roda via pg_cron.
import { createClient } from "npm:@supabase/supabase-js@2.57.2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const cutoff = new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString();

  const { data: rows, error } = await supabase
    .from("capture_link_evidence")
    .select("id, file_path")
    .lt("received_at_server", cutoff)
    .limit(500);

  if (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (!rows?.length) {
    return new Response(JSON.stringify({ deleted: 0 }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const paths = rows.map((r) => r.file_path).filter(Boolean);
  if (paths.length) {
    // remove() é best-effort: se o objeto já foi removido fora do fluxo (TTL do bucket,
    // remoção manual), continuamos e ainda assim apagamos a linha do banco — caso contrário
    // o registro fica órfão e a UI promete um download que não existe mais.
    const { error: rmErr } = await supabase.storage.from("evidence_vault").remove(paths);
    if (rmErr) console.warn("[cleanup-capture-evidence] storage.remove warning", rmErr.message);
  }
  await supabase
    .from("capture_link_evidence")
    .delete()
    .in("id", rows.map((r) => r.id));

  return new Response(JSON.stringify({ deleted: rows.length }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});

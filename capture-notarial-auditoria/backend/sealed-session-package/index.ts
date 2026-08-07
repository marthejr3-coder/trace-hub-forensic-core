// Sealed Capture — Requisitos 8, 9 e 11: recebe o Master Hash + caminhos dos
// artefatos de uma sessão já finalizada, persiste no registro da sessão
// (append-once, via service_role) e ancora criptograficamente o Master Hash
// (OriginStamp multi-chain + RFC 3161) reaproveitando `originstamp-anchor`.
import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

interface Body {
  session_id: string;
  master_hash: string;
  artifact_manifest?: Record<string, unknown> | null;
  artifact_manifest_path?: string | null;
  dom_chain_path?: string | null;
  mutations_path?: string | null;
  audit_report_path?: string | null;
  environment_tampered?: boolean | null;
  forensic_status?: "integra" | "integra_com_ressalvas" | "comprometida" | null;
  anchor?: boolean;
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const auth = req.headers.get("Authorization");
    if (!auth) return json({ error: "Unauthorized" }, 401);
    const token = auth.replace("Bearer ", "");

    const userClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
    );
    const { data: { user }, error: authErr } = await userClient.auth.getUser(token);
    if (authErr || !user) return json({ error: "Unauthorized" }, 401);

    const body = (await req.json()) as Body;
    if (!body?.session_id || !body?.master_hash) {
      return json({ error: "session_id and master_hash required" }, 400);
    }
    if (!/^[0-9a-f]{64}$/i.test(body.master_hash)) {
      return json({ error: "master_hash must be a SHA-256 hex digest" }, 400);
    }

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    const { data: session, error: sErr } = await admin
      .from("sealed_capture_sessions")
      .select("id,user_id,status,master_hash,merkle_root,target_url")
      .eq("id", body.session_id)
      .maybeSingle();
    if (sErr || !session) return json({ error: "Session not found" }, 404);
    if (session.user_id !== user.id) return json({ error: "Forbidden" }, 403);
    if (session.status === "open") return json({ error: "Session must be finalized first" }, 409);
    if (session.master_hash && session.master_hash !== body.master_hash) {
      // Append-once: o master hash de uma sessão selada não pode ser trocado.
      return json({ error: "Session already sealed with a different master_hash" }, 409);
    }

    // Ancoragem do Master Hash (não bloqueia a selagem em caso de falha).
    let anchor: unknown = null;
    let originstamp_id: string | null = null;
    if (body.anchor !== false) {
      try {
        const res = await fetch(
          `${Deno.env.get("SUPABASE_URL")}/functions/v1/originstamp-anchor`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: auth },
            body: JSON.stringify({
              hash: body.master_hash,
              comment: `Trace Hub — Captura Lacrada ${body.session_id} (master hash)`,
            }),
          },
        );
        const parsed = await res.json().catch(() => null);
        if (res.ok && parsed) {
          anchor = parsed;
          originstamp_id = (parsed as { originstamp_id?: string; id?: string })?.originstamp_id ??
            (parsed as { id?: string })?.id ?? null;
        } else {
          anchor = { error: "anchor_failed", detail: parsed };
        }
      } catch (e) {
        anchor = { error: "anchor_unreachable", detail: e instanceof Error ? e.message : String(e) };
      }
    }

    const update: Record<string, unknown> = {
      master_hash: body.master_hash,
      artifact_manifest: body.artifact_manifest ?? null,
      artifact_manifest_path: body.artifact_manifest_path ?? null,
      dom_chain_path: body.dom_chain_path ?? null,
      mutations_path: body.mutations_path ?? null,
      audit_report_path: body.audit_report_path ?? null,
      environment_tampered: body.environment_tampered ?? false,
      forensic_status: body.forensic_status ?? "integra",
      updated_at: new Date().toISOString(),
    };
    if (originstamp_id) update.originstamp_id = originstamp_id;

    const { error: uErr } = await admin
      .from("sealed_capture_sessions")
      .update(update)
      .eq("id", body.session_id);
    if (uErr) return json({ error: uErr.message }, 500);

    return json({
      success: true,
      session_id: body.session_id,
      master_hash: body.master_hash,
      merkle_root: session.merkle_root,
      originstamp_id,
      anchor,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error("sealed-session-package:", msg);
    return json({ error: msg }, 500);
  }
});

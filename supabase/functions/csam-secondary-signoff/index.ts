// csam-secondary-signoff — Edge Function ICAC two-person sign-off
//
// Recebe os dados do 2º operador (gerados no cliente) e:
//   1. Valida o JWT (auth.getUser)
//   2. Rejeita se secondary_operator_id == operator_id da sessão (N-01)
//   3. Recalcula signoff_hash server-side (não confia no client)
//   4. Insere em csam_session_signoffs via service_role
//
// Resposta:
//   200 { ok: true, signoff_hash, primary_operator_id, signed_at }
//   401 unauthorized | 409 self-attestation forbidden | 404 session not found

import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*, authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const auth = req.headers.get("Authorization");
    if (!auth?.startsWith("Bearer ")) {
      return Response.json({ error: "unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const token = auth.replace("Bearer ", "");

    const userClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
    );
    const { data: { user }, error: userErr } = await userClient.auth.getUser(token);
    if (userErr || !user) {
      return Response.json({ error: "unauthorized" }, { status: 401, headers: corsHeaders });
    }

    const body = await req.json();
    const {
      session_id,
      secondary_email,
      attested_integrity_hash,
      signoff_nonce,
      device_fingerprint,
      notes,
      case_reference,
    } = body ?? {};

    if (!session_id || !secondary_email || !attested_integrity_hash || !signoff_nonce) {
      return Response.json({ error: "missing fields" }, { status: 400, headers: corsHeaders });
    }

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // Look up scan session to get primary operator
    const { data: session, error: sessErr } = await admin
      .from("csam_scan_sessions")
      .select("id, operator_id, case_reference")
      .eq("id", session_id)
      .maybeSingle();

    if (sessErr || !session) {
      return Response.json({ error: "session not found" }, { status: 404, headers: corsHeaders });
    }

    // N-01 gate: secondary must differ from primary
    if (session.operator_id === user.id) {
      return Response.json(
        { error: "self-attestation forbidden", code: "SAME_OPERATOR" },
        { status: 409, headers: corsHeaders },
      );
    }

    const signed_at = new Date().toISOString();
    // Recalculate hash server-side; client value is ignored.
    const signoff_hash = await sha256Hex(
      `${attested_integrity_hash}|${secondary_email}|${signed_at}|${signoff_nonce}|${device_fingerprint ?? ""}`,
    );

    const { error: insErr } = await admin.from("csam_session_signoffs").insert({
      session_id: String(session_id),
      case_reference: case_reference ?? session.case_reference ?? null,
      primary_operator_id: session.operator_id,
      secondary_operator_id: user.id,
      secondary_operator_email: String(secondary_email).trim(),
      attested_integrity_hash,
      signoff_hash,
      signoff_nonce,
      signed_at,
      device_fingerprint: device_fingerprint ?? null,
      notes: notes ? String(notes).trim() : null,
    });

    if (insErr) {
      console.error("[csam-secondary-signoff] insert failed:", insErr);
      return Response.json({ error: insErr.message }, { status: 500, headers: corsHeaders });
    }

    return Response.json(
      { ok: true, signoff_hash, primary_operator_id: session.operator_id, signed_at },
      { headers: corsHeaders },
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return Response.json({ error: msg }, { status: 500, headers: corsHeaders });
  }
});

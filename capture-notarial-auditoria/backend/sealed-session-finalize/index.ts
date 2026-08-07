// Sealed Capture — finaliza a sessão:
//   1. Carrega todos os eventos da sessão (ordenados por seq)
//   2. Calcula Merkle root simples sobre event_hash[]
//   3. Insere evento 'close'
//   4. Chama originstamp-anchor com o Merkle root como evidence_hash
//   5. Marca sessão como 'anchored' com merkle_root + originstamp_id
import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "*, authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const GENESIS = "0".repeat(64);

interface Body {
  session_id: string;
  video_path?: string; // opcional: caminho relativo do MP4 já upado
  pdf_path?: string; // opcional: caminho relativo do PDF já upado
}

async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Merkle root sobre array de hashes hex (SHA-256). Promove ímpares (duplica último).
async function merkleRoot(hashes: string[]): Promise<string> {
  if (hashes.length === 0) return GENESIS;
  let level = hashes.slice();
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = level[i + 1] ?? level[i];
      next.push(await sha256Hex(`${a}${b}`));
    }
    level = next;
  }
  return level[0];
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const auth = req.headers.get("Authorization");
    if (!auth) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const token = auth.replace("Bearer ", "");

    const userClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
    );
    const { data: { user }, error: authErr } = await userClient.auth.getUser(token);
    if (authErr || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = (await req.json()) as Body;
    if (!body?.session_id) {
      return new Response(JSON.stringify({ error: "session_id required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    const { data: session, error: sErr } = await admin
      .from("sealed_capture_sessions")
      .select("id,user_id,status,target_url,started_at")
      .eq("id", body.session_id)
      .maybeSingle();
    if (sErr || !session) {
      return new Response(JSON.stringify({ error: "Session not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    if (session.user_id !== user.id) {
      return new Response(JSON.stringify({ error: "Forbidden" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    if (session.status !== "open") {
      return new Response(JSON.stringify({ error: "Session already finalized" }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Insere evento 'close' antes de coletar
    {
      const { data: last } = await admin
        .from("sealed_capture_events")
        .select("seq,event_hash")
        .eq("session_id", body.session_id)
        .order("seq", { ascending: false })
        .limit(1)
        .maybeSingle();
      const prev_hash = last?.event_hash ?? GENESIS;
      const seq = (last?.seq ?? 0) + 1;
      const created_at = new Date().toISOString();
      const payload = {
        finalized_by: user.id,
        video_path: body.video_path ?? null,
        pdf_path: body.pdf_path ?? null,
      };
      const payload_sha256 = await sha256Hex(JSON.stringify(payload));
      const event_hash = await sha256Hex(
        `${prev_hash}|${payload_sha256}|${created_at}`,
      );
      await admin.from("sealed_capture_events").insert({
        session_id: body.session_id,
        user_id: user.id,
        seq,
        event_type: "close",
        payload,
        payload_sha256,
        prev_hash,
        event_hash,
        created_at,
      });
    }

    // Coleta todos os eventos para Merkle
    const { data: events, error: eErr } = await admin
      .from("sealed_capture_events")
      .select("seq,event_hash,event_type,created_at")
      .eq("session_id", body.session_id)
      .order("seq", { ascending: true });
    if (eErr) throw eErr;
    const hashes = (events ?? []).map((e) => e.event_hash as string);
    const root = await merkleRoot(hashes);

    // Ancora no OriginStamp (OTS + RFC 3161)
    let originstamp_id: string | null = null;
    let anchor_result: unknown = null;
    try {
      const anchorRes = await fetch(
        `${Deno.env.get("SUPABASE_URL")!}/functions/v1/originstamp-anchor`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ evidence_hash: root }),
        },
      );
      anchor_result = await anchorRes.json();
      if (
        anchorRes.ok &&
        anchor_result &&
        typeof anchor_result === "object" &&
        "originstamp" in (anchor_result as Record<string, unknown>)
      ) {
        const os = (anchor_result as { originstamp?: { timestamp_id?: string } })
          .originstamp;
        originstamp_id = os?.timestamp_id ?? root;
      }
    } catch (e) {
      console.error("anchor error:", e);
    }

    // Atualiza sessão (via service_role, trigger guard não toca em service_role)
    const ended_at = new Date().toISOString();
    const video_url = body.video_path
      ? body.video_path
      : null;
    const pdf_url = body.pdf_path ? body.pdf_path : null;

    const { error: uErr } = await admin
      .from("sealed_capture_sessions")
      .update({
        ended_at,
        merkle_root: root,
        originstamp_id,
        video_url,
        pdf_url,
        status: originstamp_id ? "anchored" : "closed",
      })
      .eq("id", body.session_id);
    if (uErr) throw uErr;

    return new Response(
      JSON.stringify({
        success: true,
        session_id: body.session_id,
        ended_at,
        merkle_root: root,
        event_count: hashes.length,
        originstamp_id,
        anchor: anchor_result,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error("sealed-session-finalize:", msg);
    return new Response(JSON.stringify({ error: msg }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});

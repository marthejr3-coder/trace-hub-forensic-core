import { useCallback, useRef, useState } from 'react';
import { supabase } from '@/integrations/supabase/client';

export type SealedEventType =
  | 'navigation'
  | 'screenshot'
  | 'fullpage'
  | 'network'
  | 'console'
  | 'user_action';

export interface SealedSession {
  id: string;
  target_url: string;
  started_at: string;
}

export interface SealedFinalizeResult {
  session_id: string;
  ended_at: string;
  merkle_root: string;
  event_count: number;
  originstamp_id: string | null;
  anchor: unknown;
}

/**
 * Manages a Sealed Capture Session lifecycle:
 *  start  -> insert row in sealed_capture_sessions
 *  event  -> POST sealed-session-event
 *  finalize -> POST sealed-session-finalize (computes Merkle + anchors)
 */
export function useSealedSession() {
  const [session, setSession] = useState<SealedSession | null>(null);
  const [busy, setBusy] = useState(false);
  const [eventCount, setEventCount] = useState(0);
  const seqRef = useRef(0);

  const start = useCallback(async (targetUrl: string) => {
    setBusy(true);
    try {
      const { data: u } = await supabase.auth.getUser();
      if (!u?.user) throw new Error('Sessão expirada. Faça login novamente.');
      const ua = navigator.userAgent;
      const viewport = { width: window.innerWidth, height: window.innerHeight };
      const { data, error } = await supabase
        .from('sealed_capture_sessions')
        .insert({
          user_id: u.user.id,
          target_url: targetUrl,
          user_agent_locked: ua,
          viewport,
        })
        .select('id,target_url,started_at')
        .single();
      if (error) throw error;
      seqRef.current = 0;
      setEventCount(0);
      const s: SealedSession = {
        id: data.id,
        target_url: data.target_url,
        started_at: data.started_at,
      };
      setSession(s);
      return s;
    } finally {
      setBusy(false);
    }
  }, []);

  const logEvent = useCallback(
    async (
      event_type: SealedEventType,
      payload: Record<string, unknown>,
      sessionOverride?: SealedSession,
    ) => {
      const s = sessionOverride ?? session;
      if (!s) throw new Error('Nenhuma sessão lacrada ativa.');
      const { data, error } = await supabase.functions.invoke(
        'sealed-session-event',
        { body: { session_id: s.id, event_type, payload } },
      );
      if (error) throw error;
      setEventCount((c) => c + 1);
      return data as { seq: number; event_hash: string; created_at: string };
    },
    [session],
  );

  const finalize = useCallback(
    async (
      opts?: { video_path?: string; pdf_path?: string },
      sessionOverride?: SealedSession,
    ) => {
      const s = sessionOverride ?? session;
      if (!s) throw new Error('Nenhuma sessão lacrada ativa.');
      setBusy(true);
      try {
        const { data, error } = await supabase.functions.invoke(
          'sealed-session-finalize',
          { body: { session_id: s.id, ...opts } },
        );
        if (error) throw error;
        const result = data as SealedFinalizeResult;
        setSession(null);
        return result;
      } finally {
        setBusy(false);
      }
    },
    [session],
  );

  const proxyUrlFor = useCallback(async (url: string, sessionOverride?: SealedSession) => {
    const s = sessionOverride ?? session;
    if (!s) throw new Error('Nenhuma sessão lacrada ativa.');
    // F-02: troca o JWT longo por token opaco efêmero (TTL 5 min) antes de
    // montar a URL do iframe. Assim o JWT nunca aparece na query string nem
    // em logs de proxy/CDN.
    const { data, error } = await supabase.functions.invoke('sealed-proxy-token', {
      body: { session_id: s.id },
    });
    if (error) throw error;
    const opaque = (data as { token?: string })?.token;
    if (!opaque) throw new Error('Falha ao emitir token de proxy.');
    const base = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/sealed-proxy`;
    return `${base}?sid=${encodeURIComponent(s.id)}&u=${encodeURIComponent(url)}&t=${encodeURIComponent(opaque)}`;
  }, [session]);


  return { session, busy, eventCount, start, logEvent, finalize, proxyUrlFor };
}

import { useState, useEffect } from 'react';
import { useParams, useNavigate } from "@/lib/router-compat";
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { toast } from 'sonner';
import { Loader2, ShieldCheck, Upload, CheckCircle2, Lock, Smartphone, Hash, AlertTriangle, UserCheck, Shield, ArrowDown, FileText } from 'lucide-react';
import TraceLogo from '@/components/TraceLogo';
import CofreCard from '@/components/capture-link/CofreCard';
import {
  getDeviceInfo, requestGPS, getInternalIP, getBatteryInfo, getNetworkInfo,
  getClientHints, getWebRTCNetworkFingerprint, getDetailedHardwareInfo,
  getWebGLFingerprint, getGPUInfo, getAudioFingerprint, getCanvasFingerprint,
  getInstalledFonts, enumerateMediaDevices, getStorageEstimate,
} from '@/lib/device-info';
import { generateBrowserFingerprint } from '@/lib/browser-fingerprint';
import { hashFile, hashFileDual } from '@/lib/forensic-hash';
import { analisarImagemLocal } from '@/lib/forensic-analysis-engine';

// Coleta um dossiê forense client-side com tudo que o navegador permite expor
// sem upload extra de mídia. Usado para vincular o arquivo enviado ao dispositivo
// e à rede da vítima (cadeia de custódia — Art. 158-A a 158-F CPP).
async function collectVictimForensics() {
  const timedOut: string[] = [];
  const safeT = async <T,>(label: string, p: Promise<T> | T, ms: number, fallback: T): Promise<T> => {
    let timer: any;
    const timeout = new Promise<T>((resolve) => {
      timer = setTimeout(() => {
        timedOut.push(`${label}@${ms}ms`);
        resolve(fallback);
      }, ms);
    });
    try {
      const value = await Promise.race([Promise.resolve(p), timeout]);
      clearTimeout(timer);
      return value;
    } catch {
      clearTimeout(timer);
      return fallback;
    }
  };

  // Tudo dentro de um Promise.race global de 8s para nunca segurar a UI.
  const collector = (async () => {
    const [
      deviceInfo, internalIp, battery, network, clientHints, webrtc, hwDetail,
      webgl, gpu, audio, canvas, fonts, mediaDevices, storage, fp,
    ] = await Promise.all([
      safeT('deviceInfo', getDeviceInfo(), 3000, null as any),
      safeT('internalIp', getInternalIP(), 3000, null),
      safeT('battery', getBatteryInfo(), 1500, null),
      safeT('network', getNetworkInfo(), 1500, null),
      safeT('clientHints', getClientHints(), 1500, null),
      safeT('webrtc', getWebRTCNetworkFingerprint(), 3000, null as any),
      safeT('hwDetail', getDetailedHardwareInfo(), 2000, {} as any),
      safeT('webgl', getWebGLFingerprint(), 2000, {} as any),
      safeT('gpu', getGPUInfo(), 2000, { renderer: null, vendor: null }),
      safeT('audio', getAudioFingerprint(), 2000, null),
      safeT('canvas', getCanvasFingerprint(), 2000, null),
      safeT('fonts', getInstalledFonts(), 2000, [] as string[]),
      safeT('mediaDevices', enumerateMediaDevices(), 2000, [] as any[]),
      safeT('storage', getStorageEstimate(), 1500, { quota: null, usage: null }),
      safeT('fingerprint', generateBrowserFingerprint(), 3000, null as any),
    ]);
    return {
      collected_at: new Date().toISOString(),
      device: deviceInfo,
      fingerprint: fp,
      hardware: { ...hwDetail, gpu, webgl },
      network: {
        ...(network || {}),
        internal_ip: internalIp,
        webrtc,
        online: typeof navigator !== 'undefined' ? navigator.onLine : null,
      },
      battery,
      client_hints: clientHints,
      media_devices: mediaDevices,
      storage_estimate: storage,
      audio_fp: audio,
      canvas_fp: canvas ? canvas.slice(0, 80) + '…' : null,
      installed_fonts_sample: fonts.slice(0, 40),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezone_offset_minutes: -new Date().getTimezoneOffset(),
      languages: typeof navigator !== 'undefined' ? [...(navigator.languages || [])] : [],
      referrer: typeof document !== 'undefined' ? document.referrer || null : null,
      page_url: typeof location !== 'undefined' ? location.href : null,
      _partial_timeouts: timedOut,
    };
  })();

  const globalFallback = new Promise<any>((resolve) => {
    setTimeout(() => {
      console.warn('[capture-link] forensics global timeout (8s)', { timedOut });
      resolve({
        collected_at: new Date().toISOString(),
        _global_timeout: true,
        _partial_timeouts: timedOut,
      });
    }, 8000);
  });

  const result = await Promise.race([collector, globalFallback]);
  if (timedOut.length > 0) console.warn('[capture-link] forensics partial timeouts', timedOut);
  return result;
}

// Wrapper genérico com timeout — usado fora do coletor também.
async function withTimeout<T>(p: Promise<T>, ms: number, fallback: T, label: string): Promise<T> {
  let timer: any;
  const t = new Promise<T>((resolve) => {
    timer = setTimeout(() => {
      console.warn(`[capture-link] ${label} timeout @${ms}ms`);
      resolve(fallback);
    }, ms);
  });
  try {
    const v = await Promise.race([p, t]);
    clearTimeout(timer);
    return v;
  } catch {
    clearTimeout(timer);
    return fallback;
  }
}

// Texto do consentimento específico para o dossiê forense do dispositivo.
// Separado do aceite de autenticidade (art. 299 CP) porque a coleta de
// identificadores técnicos (fingerprints, IP interno, GPU, fontes) exige
// base legal e finalidade próprias sob a LGPD.
export const FORENSIC_DOSSIER_CONSENT_TEXT =
  'Consinto expressamente com a coleta e o tratamento dos identificadores técnicos do meu dispositivo ' +
  '(canvas fingerprint, audio fingerprint, browser fingerprint, IP interno via WebRTC, GPU, fontes instaladas, ' +
  'Client Hints, bateria e uso de armazenamento), com finalidade exclusiva de compor a cadeia de custódia da ' +
  'prova junto à autoridade responsável pelo meu caso, reconhecendo como base legal o exercício regular de ' +
  'direitos e o legítimo interesse do titular do direito violado (LGPD, art. 7º, VI e IX, e art. 11, II, \'d\' e \'f\').';

interface Session {
  id: string;
  token: string;
  status: 'waiting' | 'active' | 'completed' | 'expired';
  expires_at: string;
}

export default function CaptureLinkVictim() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState<'intro' | 'uploading' | 'success' | 'expired'>('intro');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [lastFileHash, setLastFileHash] = useState<string | null>(null);
  const [aiWarning, setAiWarning] = useState<{veredicto: string, pontuacao: number} | null>(null);
  const [identity, setIdentity] = useState({
    full_name: '', rg: '', rg_uf: '', cpf: '', phone: '', email: '',
    declaration: false,
  });
  const [partyNotes, setPartyNotes] = useState('');
  const PARTY_NOTES_MAX = 4000;
  const [custodyConsent, setCustodyConsent] = useState(false);
  const [forensicDossierConsent, setForensicDossierConsent] = useState(false);
  const identityValid = identity.full_name.trim().length >= 5
    && identity.rg.trim().length >= 4
    && custodyConsent
    && forensicDossierConsent;

  useEffect(() => {
    const fetchSession = async () => {
      if (!token) return;
      
      const { data: rows, error } = await (supabase as any)
        .rpc('get_capture_session_by_token', { p_token: token });
      const data = Array.isArray(rows) ? rows[0] : rows;

      if (error || !data) {
        setStatus('expired');
        setLoading(false);
        return;
      }

      const now = new Date();
      const expiresAt = new Date(data.expires_at);

      if (data.status === 'expired' || expiresAt < now) {
        setStatus('expired');
      } else {
        setSession(data as Session);
        // Marcar como ativa se estiver aguardando
        if (data.status === 'waiting') {
          await supabase
            .from('capture_link_sessions')
            .update({ status: 'active' } as any)
            .eq('id', data.id);
        }
      }
      setLoading(false);
    };

    fetchSession();
  }, [token]);

  const MAX_UPLOAD_BYTES = 600 * 1024 * 1024; // 600 MB

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !session) return;

    if (!identityValid) {
      toast.error('Preencha nome completo, RG e marque os dois consentimentos antes de enviar.');
      return;
    }

    if (file.size > MAX_UPLOAD_BYTES) {
      toast.error(`Arquivo excede 600 MB (tamanho: ${(file.size / 1024 / 1024).toFixed(1)} MB). Comprima o vídeo antes de enviar.`);
      return;
    }

    setStatus('uploading');
    setUploadProgress(10);
    
    // Smooth progress simulation for steps that don't have native progress events
    const simulateProgress = (start: number, end: number, duration: number) => {
      const startTime = Date.now();
      const tick = () => {
        const now = Date.now();
        const elapsed = now - startTime;
        const progress = Math.min(start + (elapsed / duration) * (end - start), end);
        setUploadProgress(Math.floor(progress));
        if (progress < end) {
          requestAnimationFrame(tick);
        }
      };
      requestAnimationFrame(tick);
    };

    try {
      // 1. Coletar metadados do dispositivo + dossiê forense completo (10% -> 30%)
      // Todos os passos têm timeout próprio para não travar a UI em redes ruins.
      simulateProgress(10, 30, 2000);
      const deviceInfo = await withTimeout(
        Promise.resolve(getDeviceInfo()),
        3000,
        { user_agent: navigator.userAgent, os: 'unknown', browser: 'unknown' } as any,
        'getDeviceInfo',
      );
      const location = await withTimeout(requestGPS().catch(() => null), 4000, null, 'requestGPS');
      const forensics = await collectVictimForensics().catch(() => null);
      const fileIntrinsic = await (async () => {
        try {
          const { extractFileIntrinsicMetadata } = await import('@/lib/file-intrinsic-metadata');
          return await extractFileIntrinsicMetadata(file);
        } catch (err) {
          console.warn('[capture-link] file-intrinsic extractor falhou:', err);
          return null;
        }
      })();

      // 2. Gerar Hash CLIENT-SIDE (Web Crypto API) (30% -> 50%)
      simulateProgress(30, 50, 1500);
      const { sha256: clientHash, sha512: clientHashSha512 } = await hashFileDual(file);
      setLastFileHash(clientHash);


      // 3. Upload para Storage (50% -> 75%)
      simulateProgress(50, 75, 3000);
      const fileExt = file.name.split('.').pop();
      const filePath = `capture_link/${session.id}/${crypto.randomUUID()}.${fileExt}`;

      const { error: uploadError } = await supabase.storage
        .from('evidence_vault')
        .upload(filePath, file, {
          cacheControl: '3600',
          upsert: false
        });

      if (uploadError) throw uploadError;

      // 3b. Detecção de IA ANTES do insert. RLS impede UPDATE pelo anon, então
      // embutimos o resultado direto na metadata inicial em vez de fazer um
      // UPDATE posterior (que silenciosamente afetava 0 linhas). (75% -> 85%)
      simulateProgress(75, 85, 1500);
      let aiMetadata: any = null;
      if (file.type.startsWith('image/')) {
        try {
          const reader = new FileReader();
          const base64Promise = new Promise<string>((resolve) => {
            reader.onload = () => {
              const res = reader.result as string;
              resolve(res.split(',')[1]);
            };
            reader.readAsDataURL(file);
          });
          const previewUrl = URL.createObjectURL(file);

          const [, localRes] = await Promise.all([
            base64Promise,
            analisarImagemLocal(file, previewUrl).catch((e) => {
              console.error('Motor local falhou:', e);
              return null;
            }),
          ]);

          URL.revokeObjectURL(previewUrl);

          aiMetadata = {
            ai_detection_local: localRes
              ? {
                  veredicto: localRes.veredicto,
                  pontuacao: localRes.pontuacao,
                  conclusao: localRes.conclusao,
                  analyzed_at: new Date().toISOString(),
                }
              : null,
          };

          const localIsAI = localRes?.veredicto === 'Gerada por IA' && localRes.pontuacao > 60;
          if (localIsAI && localRes) {
            setAiWarning({ veredicto: localRes.veredicto, pontuacao: localRes.pontuacao });
          }
        } catch (e) {
          console.error('Erro na detecção de IA:', e);
        }
      }

      // 4. Registrar evidência com ID pré-gerado client-side.
      // CRÍTICO: a RLS de capture_link_evidence permite INSERT anon mas NÃO
      // permite SELECT anon — então .select().single() lançava "no rows",
      // o catch revertia para 'intro' e a vítima nunca via a tela de sucesso.
      // Geramos o UUID localmente e passamos adiante sem ler de volta.
      simulateProgress(85, 92, 1000);
      const evidenceId = crypto.randomUUID();
      const { error: dbError } = await supabase
        .from('capture_link_evidence')
        .insert({
          id: evidenceId,
          session_id: session.id,
          file_name: file.name,
          file_path: filePath,
          file_size: file.size,
          mime_type: file.type,
          hash_client: clientHash,
          hash_server: clientHash, // será sobrescrito por verify-evidence-hash
          hash_client_sha512: clientHashSha512,
          hashes_match: false, // verify-evidence-hash atualiza para true se ok
          captured_at_client: new Date().toISOString(),
          ip_address: 'waiting_server',
          user_agent: deviceInfo.user_agent,
          device_model: `${deviceInfo.os} ${deviceInfo.browser}`,
          geolocation: location ? (location as any) : null,
          party_notes: partyNotes.trim() ? partyNotes.trim().slice(0, PARTY_NOTES_MAX) : null,
          metadata: {
            victim_identity: {
              full_name: identity.full_name.trim(),
              rg: identity.rg.trim(),
              rg_uf: identity.rg_uf.trim() || null,
              cpf: identity.cpf.trim() || null,
              phone: identity.phone.trim() || null,
              email: identity.email.trim() || null,
              declared_at: new Date().toISOString(),
              declaration_accepted: custodyConsent,
              declaration_text: 'Declaro, sob as penas do art. 299 do Código Penal, que o arquivo foi capturado/produzido por este dispositivo e que as informações acima são verdadeiras.',
              forensic_dossier_consent: forensicDossierConsent,
              forensic_dossier_consent_text: FORENSIC_DOSSIER_CONSENT_TEXT,
            },
            forensics,
            file_intrinsic: fileIntrinsic,
            ...(aiMetadata || {}),
          }
        });

      if (dbError) throw dbError;

      // 4b. Validação independente do servidor — rehasheia o blob direto do
      // bucket e atualiza hash_server/hash_server_sha512/hashes_match.
      // Disparo paralelo (não bloqueia a UI).
      supabase.functions
        .invoke('verify-evidence-hash', { body: { evidence_id: evidenceId, hash_client_prefix: clientHash.slice(0, 8) } })
        .then(({ error }) => {
          if (error) console.error('Server hash verification failed:', error);
        })
        .catch((e) => console.error('Server hash verification error:', e));

      // 5. Selo temporal OTS + RFC 3161 (92% -> 100%).
      // A emissão agora é feita pelo backend dentro de verify-evidence-hash,
      // logo após o servidor recalcular o hash do arquivo no storage. Isso evita
      // depender de INSERT anônimo em capture_link_timestamp_proofs e impede que
      // o selo Bitcoin só comece a contar quando o operador clicar em atualizar.
      simulateProgress(92, 100, 2000);
      await new Promise(r => setTimeout(r, 1200));

      setUploadProgress(100);
      await new Promise(r => setTimeout(r, 800));
      setStatus('success');
    } catch (err: any) {
      console.error('Upload error:', err);
      const msg = String(err?.message || err || '');
      let friendly = 'Erro ao enviar prova: ' + msg;
      if (/timeout|aborted|network/i.test(msg)) {
        friendly = 'Conexão instável durante o envio. Toque em Enviar novamente — vamos retomar do zero.';
      } else if (/memory|allocation|quota/i.test(msg) || msg.includes('hash do arquivo')) {
        friendly = 'Arquivo muito grande para processar neste celular. Tente em um computador ou divida o export do Telegram em partes menores.';
      }
      toast.error(friendly);
      setStatus('intro');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (status === 'expired') {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md w-full border-destructive/20 bg-destructive/5 text-center p-8 space-y-4">
          <div className="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
            <Lock className="w-8 h-8 text-destructive" />
          </div>
          <CardTitle className="text-xl font-bold">Link Expirado</CardTitle>
          <CardDescription>
            Este link de captura não é mais válido ou já foi concluído pelo operador.
          </CardDescription>
          <Button variant="outline" onClick={() => navigate('/')} className="w-full">
            Voltar ao Início
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col items-center p-4 py-12 md:py-20">
      <div className="mb-10 text-center space-y-2">
        <TraceLogo size="sm" />
        <p className="text-[10px] uppercase tracking-[0.2em] font-black opacity-40">Preservação de Prova Digital</p>
      </div>

      <div className="w-full max-w-lg">
        {status === 'intro' && (
          <Card className="border-2 border-primary/10 shadow-xl overflow-hidden">
            <div className="bg-primary/5 p-6 border-b border-primary/10">
              <h1 className="text-xl font-black tracking-tight mb-2">Enviar Prova com Validade Jurídica</h1>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Olá! Siga os passos abaixo para enviar sua prova com segurança.
              </p>
            </div>
            <CardContent className="p-6 space-y-6">
              <div className="space-y-4">
                <div className="flex gap-4 p-5 rounded-2xl bg-primary/5 border-2 border-primary/10 shadow-sm animate-in fade-in slide-in-from-left-4 duration-500 hover:bg-primary/[0.07] transition-colors group">
                  <div className="shrink-0 w-12 h-12 rounded-2xl bg-primary text-white flex items-center justify-center font-black shadow-lg group-hover:scale-110 transition-transform text-xl">
                    1
                  </div>
                  <div className="flex-1 pt-1">
                    <h3 className="text-base font-black text-primary">Escolher o Arquivo</h3>
                    <p className="text-[12px] text-muted-foreground leading-tight">Mais abaixo aparece o botão verde para escolher sua foto, vídeo ou PDF. <strong>Continue descendo a tela.</strong></p>
                  </div>
                </div>
                
                <div className="flex gap-4 p-5 rounded-2xl bg-muted/20 border-2 border-transparent opacity-60">
                  <div className="shrink-0 w-12 h-12 rounded-2xl bg-muted-foreground/30 text-white flex items-center justify-center font-black text-xl">
                    2
                  </div>
                  <div className="flex-1 pt-1">
                    <h3 className="text-base font-black">Aguarde o Carregamento</h3>
                    <p className="text-[12px] text-muted-foreground leading-tight">O sistema vai criar um selo de segurança digital oficial.</p>
                  </div>
                </div>

                <div className="flex gap-4 p-5 rounded-2xl bg-muted/20 border-2 border-transparent opacity-60">
                  <div className="shrink-0 w-12 h-12 rounded-2xl bg-muted-foreground/30 text-white flex items-center justify-center font-black text-xl">
                    3
                  </div>
                  <div className="flex-1 pt-1">
                    <h3 className="text-base font-black">Confirmação</h3>
                    <p className="text-[12px] text-muted-foreground leading-tight">Você verá um selo verde quando terminar. Pronto!</p>
                  </div>
                </div>
              </div>

              {/* Indicador animado: continue descendo */}
              <div className="flex flex-col items-center justify-center gap-2 py-2">
                <p className="text-[13px] font-bold text-primary text-center">
                  Continue descendo a tela ↓
                </p>
                <div className="animate-bounce">
                  <ArrowDown className="w-8 h-8 text-primary" strokeWidth={3} />
                </div>
                <p className="text-[11px] text-muted-foreground text-center max-w-[260px]">
                  Os passos acima são apenas explicação. O botão para enviar está logo abaixo.
                </p>
              </div>
              {/* Aviso de coleta para cadeia de custódia — vítima precisa ler e concordar */}
              <div className="space-y-3 rounded-2xl border-2 border-amber-500/30 bg-amber-500/[0.06] p-4">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-amber-600" />
                  <h3 className="text-sm font-black uppercase tracking-wider text-amber-700 dark:text-amber-400">
                    Trace-Hub · Coleta para cadeia de custódia
                  </h3>
                </div>
                <p className="text-[12px] text-muted-foreground leading-relaxed">
                  Você está enviando um arquivo para a <strong>autoridade policial responsável pelo seu caso</strong>.
                  Para garantir que essa prova possa ser usada, vamos registrar algumas informações junto com o arquivo.
                </p>
                <div className="rounded-xl bg-background/60 border border-amber-500/20 p-3 space-y-1.5">
                  <p className="text-[11px] font-bold uppercase tracking-wider opacity-70">
                    O que será coletado junto com o seu arquivo:
                  </p>
                  <ul className="text-[12px] text-muted-foreground space-y-1 list-disc pl-4">
                    <li>Localização aproximada do seu dispositivo no momento do envio</li>
                    <li>Informações técnicas do aparelho e navegador (modelo, sistema, identificadores)</li>
                    <li>Data e hora exatas do envio, com registro de integridade (hash)</li>
                  </ul>
                </div>
                <p className="text-[11px] text-muted-foreground leading-snug">
                  Essas informações ajudam a comprovar que o arquivo é original, foi enviado por você e não foi alterado depois.
                  Elas serão usadas exclusivamente pela autoridade responsável pelo seu caso, como parte do processo.
                </p>
                <label className="flex items-start gap-2 cursor-pointer rounded-lg p-2 hover:bg-amber-500/5 transition">
                  <input
                    type="checkbox"
                    checked={custodyConsent}
                    onChange={(e) => setCustodyConsent(e.target.checked)}
                    className="mt-1 w-4 h-4 accent-amber-600 shrink-0"
                  />
                  <span className="text-[12px] leading-snug">
                    Declaro que o arquivo enviado foi produzido por mim/meu dispositivo, que as informações são verdadeiras,
                    e autorizo a coleta dos dados técnicos acima para fins de cadeia de custódia
                    (<strong>art. 299 do Código Penal</strong>).
                  </span>
                </label>
                {/* Consentimento próprio para o dossiê forense do dispositivo (LGPD) */}
                <label className="flex items-start gap-2 cursor-pointer rounded-lg p-2 border border-amber-500/20 bg-background/60 hover:bg-amber-500/5 transition">
                  <input
                    type="checkbox"
                    checked={forensicDossierConsent}
                    onChange={(e) => setForensicDossierConsent(e.target.checked)}
                    className="mt-1 w-4 h-4 accent-amber-600 shrink-0"
                  />
                  <span className="text-[12px] leading-snug">
                    Consinto expressamente com a coleta e o tratamento dos <strong>identificadores técnicos do meu
                    dispositivo</strong> (canvas fingerprint, audio fingerprint, browser fingerprint, IP interno via WebRTC,
                    GPU, fontes instaladas, Client Hints, bateria e uso de armazenamento), com finalidade exclusiva de compor
                    a cadeia de custódia da prova junto à autoridade responsável pelo meu caso, reconhecendo como base legal
                    o exercício regular de direitos e o legítimo interesse do titular do direito violado
                    (<strong>LGPD, art. 7º, VI e IX, e art. 11, II, ‘d’ e ‘f’</strong>).
                  </span>
                </label>
              </div>

              {/* Identificação da vítima — vincula o arquivo à pessoa para cadeia de custódia */}
              <div className="space-y-3 rounded-2xl border-2 border-primary/10 bg-primary/[0.03] p-4">
                <div className="flex items-center gap-2">
                  <UserCheck className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-black uppercase tracking-wider">Sua identificação oficial</h3>
                </div>
                <p className="text-[11px] text-muted-foreground leading-snug">
                  Necessária para vincular o arquivo a você na cadeia de custódia (Art. 158-A CPP). Dados protegidos pela LGPD.
                </p>
                <div className="grid grid-cols-1 gap-2">
                  <Input placeholder="Nome completo conforme RG *" value={identity.full_name}
                    onChange={(e) => setIdentity(p => ({ ...p, full_name: e.target.value }))} maxLength={120} />
                  <div className="grid grid-cols-3 gap-2">
                    <Input className="col-span-2" placeholder="RG *" value={identity.rg}
                      onChange={(e) => setIdentity(p => ({ ...p, rg: e.target.value }))} maxLength={20} />
                    <Input placeholder="UF" value={identity.rg_uf}
                      onChange={(e) => setIdentity(p => ({ ...p, rg_uf: e.target.value.toUpperCase() }))} maxLength={2} />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Input placeholder="CPF (opcional)" value={identity.cpf}
                      onChange={(e) => setIdentity(p => ({ ...p, cpf: e.target.value }))} maxLength={14} />
                    <Input placeholder="Telefone (opcional)" value={identity.phone}
                      onChange={(e) => setIdentity(p => ({ ...p, phone: e.target.value }))} maxLength={20} />
                  </div>
                  <Input type="email" placeholder="E-mail (opcional)" value={identity.email}
                    onChange={(e) => setIdentity(p => ({ ...p, email: e.target.value }))} maxLength={120} />
                </div>
              </div>


              {/* Observações da parte — vai para o laudo e pacote judicial */}
              <div className="space-y-2 rounded-2xl border-2 border-primary/10 bg-background p-4">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-black uppercase tracking-wider">Observações (opcional)</h3>
                </div>
                <p className="text-[11px] text-muted-foreground leading-snug">
                  Use este espaço para contextualizar a prova. Exemplo: <em>"O site do golpe já estava fora do ar, por isso usei o Wayback Machine (link do snapshot) para registrar o conteúdo original."</em>
                  <br />Tudo o que escrever aqui será incluído no laudo e no pacote para peticionamento. <strong>Não inclua dados sigilosos de terceiros.</strong>
                </p>
                <Textarea
                  value={partyNotes}
                  onChange={(e) => setPartyNotes(e.target.value.slice(0, PARTY_NOTES_MAX))}
                  placeholder="Ex.: O site golpista (https://exemplo-golpe.com) saiu do ar em DD/MM/AAAA. Snapshot Wayback Machine: https://web.archive.org/web/.../https://exemplo-golpe.com"
                  rows={4}
                  maxLength={PARTY_NOTES_MAX}
                  className="text-sm"
                />
                <div className="flex justify-end">
                  <span className="text-[10px] text-muted-foreground font-mono">{partyNotes.length} / {PARTY_NOTES_MAX}</span>
                </div>
              </div>

              <div className="relative pt-4">
                <Input 
                  type="file" 
                  className="hidden" 
                  id="forensic-upload" 
                  onChange={handleFileUpload}
                  accept="image/*,video/*,audio/*,application/pdf,application/zip,application/x-zip-compressed,application/x-zip,application/x-rar-compressed,application/x-7z-compressed,application/x-tar,application/gzip,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-outlook,message/rfc822,text/plain,text/csv,text/html,application/json,application/xml,application/octet-stream,.zip,.rar,.7z,.tar,.gz,.jpg,.jpeg,.png,.webp,.heic,.heif,.gif,.bmp,.tiff,.tif,.svg,.mp4,.mov,.avi,.mkv,.webm,.m4v,.3gp,.3g2,.flv,.wmv,.mpg,.mpeg,.ts,.mts,.m2ts,.mp3,.aac,.ogg,.opus,.wav,.m4a,.flac,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.odt,.ods,.rtf,.txt,.csv,.tsv,.json,.xml,.html,.htm,.eml,.msg,.mbox,.vcf,.ics,.log"
                />
                <Button asChild={identityValid} disabled={!identityValid}
                  className="w-full h-20 text-xl font-black gap-4 shadow-2xl shadow-primary/40 hover:scale-[1.02] active:scale-95 transition-all rounded-2xl relative overflow-hidden group disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100">
                  {identityValid ? (
                    <Label htmlFor="forensic-upload" className="cursor-pointer w-full h-full flex items-center justify-center">
                      <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000" />
                      <Upload className="w-8 h-8 animate-bounce" />
                      SELECIONAR ARQUIVO
                    </Label>
                  ) : (
                    <span className="flex items-center justify-center gap-3"><Lock className="w-6 h-6" /> Preencha sua identificação</span>
                  )}
                </Button>
                <div className="mt-4 space-y-2">
                  <p className="text-center text-[11px] text-muted-foreground font-medium bg-muted/30 p-2 rounded-lg">
                    🔒 Conexão Segura e Criptografada · Limite por arquivo: <strong>600 MB</strong>
                  </p>
                  <p className="text-center text-[11px] text-amber-600 dark:text-amber-400 font-semibold bg-amber-500/10 border border-amber-500/30 p-2 rounded-lg leading-snug">
                    ⏱ Aviso de privacidade: este arquivo e seus metadados são <strong>excluídos automaticamente em 72 horas</strong> após o envio. Garanta que o operador colete o laudo dentro desse prazo.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {status === 'uploading' && (
          <Card className="p-10 text-center space-y-6 border-2 border-primary/20 shadow-2xl animate-in zoom-in duration-300">
            <div className="relative w-32 h-32 mx-auto">
              <div className="absolute inset-0 border-8 border-primary/10 rounded-full" />
              <div 
                className="absolute inset-0 border-8 border-primary rounded-full border-t-transparent animate-spin" 
                style={{ animationDuration: '1.2s' }}
              />
              <div className="absolute inset-0 flex items-center justify-center flex-col">
                <span className="text-2xl font-black text-primary">{Math.min(uploadProgress, 99)}%</span>
                <span className="text-[10px] uppercase font-bold opacity-40">
                  {uploadProgress < 30 ? 'Iniciando' : 
                   uploadProgress < 70 ? 'Criptografando' : 
                   uploadProgress < 85 ? 'Transmitindo' : 'Finalizando'}
                </span>
              </div>
            </div>
            <div className="space-y-3">
              <h2 className="text-xl font-black">Quase lá!</h2>
              <p className="text-sm text-muted-foreground px-4 leading-relaxed">
                Estamos gerando o selo de segurança digital da sua prova. <strong>Não feche esta página</strong> para garantir a validade jurídica.
              </p>
            </div>
          </Card>
        )}

        {status === 'success' && (
          <Card className="border-emerald-500/30 bg-emerald-500/5 overflow-hidden animate-in fade-in slide-in-from-bottom-8 duration-700 shadow-2xl">
            <div className="p-10 text-center space-y-6">
              <div className="w-24 h-24 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto shadow-inner border-2 border-emerald-500/30">
                <CheckCircle2 className="w-12 h-12 text-emerald-600 animate-in zoom-in duration-1000" />
              </div>
              <div className="space-y-2">
                <h2 className="text-3xl font-black text-emerald-700 dark:text-emerald-400">Sucesso!</h2>
                <p className="text-sm font-medium text-muted-foreground">
                  Sua prova foi enviada e selada com segurança.
                </p>
              </div>

              <div className="p-5 bg-background border-2 border-emerald-500/20 rounded-2xl space-y-4 text-left shadow-sm">
                <div className="flex items-center gap-2 pb-2 border-b border-emerald-500/10">
                  <ShieldCheck className="w-5 h-5 text-emerald-500" />
                  <span className="text-xs font-black uppercase tracking-widest text-emerald-700">Protocolo de Segurança</span>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-[10px] uppercase font-black opacity-40">DNA do Arquivo (SHA-256)</Label>
                  <p className="font-mono text-[11px] break-all bg-emerald-500/5 p-3 rounded-xl border border-emerald-500/10 text-emerald-800 dark:text-emerald-200 leading-tight">
                    {lastFileHash}
                  </p>
                </div>
                <p className="text-[10px] text-muted-foreground italic leading-tight">
                  Este código único prova que o arquivo recebido é exatamente o mesmo que você enviou, sem qualquer alteração.
                </p>
              </div>

                {aiWarning && (
                  <div className="p-4 bg-red-500/10 border-2 border-red-500/30 rounded-2xl space-y-2 text-left animate-in shake-1 duration-500">
                    <div className="flex items-center gap-2 text-red-600 font-black uppercase text-[10px] tracking-widest">
                      <AlertTriangle className="w-4 h-4" />
                      Aviso de Integridade
                    </div>
                    <p className="text-xs font-bold text-red-700 leading-tight">
                      Atenção: Nossa análise IA detectou uma alta probabilidade ({Math.round(aiWarning.pontuacao)}%) desta imagem ter sido gerada artificialmente.
                    </p>
                    <p className="text-[10px] text-red-600/80 leading-snug">
                      Recomendamos encaminhar este arquivo para perícia técnica oficial para ratificação, pois evidências geradas por IA podem ser invalidadas em juízo se não forem devidamente fundamentadas.
                    </p>
                  </div>
                )}

                <div className="pt-6 flex flex-col gap-4">
                <Button onClick={() => setStatus('intro')} size="lg" variant="default" className="w-full h-14 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-lg rounded-xl shadow-lg shadow-emerald-600/20">
                  Enviar Outro Arquivo
                </Button>
                <div className="flex items-center justify-center gap-2 text-muted-foreground">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <p className="text-[11px] font-bold uppercase tracking-wider">
                    Operador notificado em tempo real
                  </p>
                </div>
              </div>
            </div>

            {/* Cofre 72h — download para peticionamento judicial */}
            {token && (
              <div className="p-5 pt-0">
                <CofreCard token={token} compact />
              </div>
            )}
          </Card>
        )}
      </div>


      <footer className="mt-20 text-center space-y-4 max-w-sm">
        <div className="flex items-center justify-center gap-6 opacity-30 grayscale hover:grayscale-0 transition-all">
          <img src="/placeholder.svg" alt="ISO 27037" className="h-6" />
          <div className="h-4 w-px bg-foreground/20" />
          <ShieldCheck className="w-6 h-6" />
        </div>
        <p className="text-[9px] text-muted-foreground leading-relaxed">
          Esta ferramenta utiliza criptografia de ponta a ponta e hashes client-side para garantir a validade jurídica da sua prova conforme o Art. 158 do CPP.
        </p>
      </footer>
    </div>
  );
}

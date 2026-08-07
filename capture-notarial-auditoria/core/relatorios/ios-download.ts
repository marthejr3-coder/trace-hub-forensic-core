/**
 * Utilitário central para downloads compatíveis com iOS Safari.
 *
 * Safari iOS bloqueia `<a download>` programático fora do gesture original do
 * usuário (após `await` em geração de PDF, por exemplo). A solução padrão é:
 *
 * 1. Abrir um popup placeholder DENTRO do onClick (`openPopupForDownload`)
 * 2. Após gerar o blob, navegar esse popup para o blob URL (`downloadBlob`)
 *
 * Em desktop/Android, o popup retorna `null` e o download segue o caminho
 * clássico com `<a download>`.
 */

/** Detecta iOS (iPhone/iPad/iPod). iPad moderno se identifica como Mac. */
export function isIOS(): boolean {
  if (typeof navigator === 'undefined') return false;
  const ua = navigator.userAgent || '';
  return (
    /iPad|iPhone|iPod/.test(ua) ||
    (ua.includes('Mac') && typeof document !== 'undefined' && 'ontouchend' in document)
  );
}

/**
 * Abre um popup placeholder com loader. Chamar SEMPRE dentro do onClick
 * (síncrono, antes de qualquer `await`) para preservar o gesture do usuário.
 *
 * Retorna `null` em desktop/Android — esses navegadores não precisam.
 */
export function openPopupForDownload(message = 'Gerando arquivo…'): Window | null {
  if (!isIOS()) return null;

  try {
    const popup = window.open('', '_blank');
    if (!popup) return null;

    popup.document.write(`
      <!doctype html>
      <html lang="pt-BR">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <title>${message}</title>
          <style>
            html,body{margin:0;height:100%;background:#0b0b0b;color:#e5e5e5;
              font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
              display:flex;align-items:center;justify-content:center;text-align:center;padding:24px}
            .spinner{width:38px;height:38px;border:3px solid #333;border-top-color:#22c55e;
              border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 16px}
            @keyframes spin{to{transform:rotate(360deg)}}
            small{display:block;opacity:.7;margin-top:12px;font-size:13px}
          </style>
        </head>
        <body>
          <div>
            <div class="spinner"></div>
            <strong>${message}</strong>
            <small>Em instantes o arquivo abrirá aqui. Use Compartilhar → Salvar em Arquivos.</small>
          </div>
        </body>
      </html>
    `);
    return popup;
  } catch {
    return null;
  }
}

/**
 * Download universal de um Blob. Usa o popup pré-aberto em iOS, ou cria um
 * `<a download>` clássico em desktop/Android.
 */
export function downloadBlob(
  blob: Blob,
  filename: string,
  popup?: Window | null,
): void {
  const url = URL.createObjectURL(blob);
  const ios = isIOS();

  if (ios && popup && !popup.closed) {
    try {
      popup.location.href = url;
    } catch {
      try {
        popup.document.open();
        popup.document.write(
          `<title>${filename}</title>` +
            `<iframe src="${url}" style="border:0;width:100%;height:100vh"></iframe>`,
        );
        popup.document.close();
      } catch {
        /* desiste e cai no path padrão abaixo */
      }
    }
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    return;
  }

  if (ios) {
    // iOS sem popup (bloqueado): navega aba atual
    window.location.href = url;
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    return;
  }

  // Desktop / Android: download clássico
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 3000);

  if (popup && !popup.closed) {
    try { popup.close(); } catch { /* noop */ }
  }
}

/**
 * Abre uma URL existente (estática ou remota) no popup pré-aberto.
 * Útil para PDFs servidos diretamente do `/public` ou Edge Function que
 * devolve URL.
 */
export function openUrlInPopup(url: string, popup?: Window | null): void {
  const ios = isIOS();
  if (ios && popup && !popup.closed) {
    try {
      popup.location.href = url;
      return;
    } catch {
      /* fallback abaixo */
    }
  }
  if (ios) {
    window.location.href = url;
    return;
  }
  const a = document.createElement('a');
  a.href = url;
  a.target = '_blank';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  if (popup && !popup.closed) {
    try { popup.close(); } catch { /* noop */ }
  }
}

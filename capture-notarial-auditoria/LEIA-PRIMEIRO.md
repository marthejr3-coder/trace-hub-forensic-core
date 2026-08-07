# Capture Notarial — código-fonte para auditoria independente

Este pacote reúne, **sem alterações**, o código-fonte que compõe o módulo
**Capture Notarial** do Trace Hub (captura de conteúdo web para fins probatórios,
CPC art. 411, II). O objetivo é permitir que um perito, advogado ou pesquisador
audite o método de forma independente, linha por linha.

Nenhum arquivo foi reescrito, reformatado ou reduzido: os arquivos são cópias
byte a byte da árvore do projeto, para que o hash conferido pelo perito coincida
com o repositório publicado.

## Estrutura

```text
frontend/paginas/        telas do fluxo (Trace Capture, Ambiente Selado, captura por
                         link, verificadores públicos, auditoria pública, certidão
                         de ancoragem, pacote de evidência)
frontend/componentes/    abas do Capture Notarial: Ata Notarial Digital, Gravação de
                         Tela, Captura Seletiva, Cadeia de Custódia, launcher do
                         ambiente selado e componentes forenses de apoio
core/integridade/        primitivas de integridade: SHA-256 incremental, cadeia de
                         hash do DOM, cadeia de quadros do vídeo, manifesto de
                         artefatos + master hash, detector de tamper, relatório de
                         auditoria e empacotador ZIP da sessão lacrada
core/relatorios/         geradores de PDF/ZIP, metodologia forense (ISO/IEC 27037),
                         bloco de verificação independente, procedência da
                         plataforma, bloco de cadeia de custódia
core/selos/              carimbo de tempo RFC 3161 e verificação OpenTimestamps
core/gravacao/           gravação em disco (OPFS) com hashing em tempo real, upload
                         retomável, garantia de trilha de áudio, download do vídeo
backend/                 funções de servidor: proxy da sessão lacrada, registro
                         encadeado de eventos, finalização/selagem, empacotamento,
                         ancoragem (OriginStamp/Bitcoin), verificação de hash,
                         confirmação de bloco e downloads de prova
testes/                  testes unitários existentes desses módulos
MANIFEST.sha256.txt      SHA-256 de cada arquivo deste pacote
```

## Fluxo auditável, em ordem

1. **Coleta** — a página alvo é aberta em ambiente controlado (aba selada via
   proxy) ou capturada por link. Cada evento relevante é registrado.
2. **Observação** — `core/integridade/dom-chain.ts` encadeia snapshots do DOM
   (`chain_hash = SHA-256(prev_hash | dom_sha256 | timestamp)`);
   `capture-observation.ts` faz o mesmo com quadros amostrados do vídeo.
   Quando o conteúdo é uma superfície externa compartilhada pelo operador, a
   gravação é classificada como *pixel-only* e isso fica declarado no manifesto.
3. **Artefatos** — vídeo, screenshots e PDF recebem SHA-256 individual
   (`core/integridade/hash.ts`, com hashing incremental por blocos).
4. **Master hash** — `artifact-manifest.ts` serializa o manifesto em JSON
   canônico (chaves ordenadas, sem espaços) e calcula o SHA-256 do conjunto.
5. **Temporalidade** — o master hash é submetido a carimbo RFC 3161 (FreeTSA) e
   ancorado em blockchain via OpenTimestamps/OriginStamp. O status só é
   apresentado como confirmado quando existe altura de bloco Bitcoin real.
6. **Entrega** — `core/relatorios/notarial-evidence-zip.ts` monta um único ZIP
   com o relatório em PDF, os selos `.ots`/`.tsr` (somente quando emitidos),
   o hash, o roteiro de verificação independente e a mídia.
7. **Contra-exame** — as páginas de verificação recalculam tudo no navegador do
   auditor, sem transmitir arquivos, e o verificador offline
   (`core/integridade/package.ts`) revalida um ZIP inteiro.

## Escopo e limites (leia antes de concluir qualquer coisa)

- O método atesta **integridade** do que foi capturado, **cadeia de custódia**
  desde a captura e **anterioridade temporal** do hash.
- O método **não** atesta a veracidade ou autenticidade do conteúdo de origem,
  assim como o reconhecimento cartorial atesta a cópia e não o documento-fonte.
- Ancoragem em blockchain e RFC 3161 provam que o hash existia antes de um
  instante; não provam o que o conteúdo significava.
- Nada aqui substitui perícia. A plataforma produz **medição**; a conclusão é do
  operador do direito ou do perito.

## Verificando este pacote

```sh
# Linux/macOS
sha256sum -c MANIFEST.sha256.txt

# Windows
certutil -hashfile <arquivo> SHA256
```

## O que NÃO está neste pacote

Chaves, tokens, variáveis de ambiente, dados de usuários e evidências reais.
As referências a segredos aparecem apenas como nomes de variáveis de ambiente
(ex.: `Deno.env.get("...")`), sem valores.

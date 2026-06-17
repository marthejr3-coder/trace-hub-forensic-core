# Trace Hub — Forensic Core (Auditoria Pública)

Repositório oficial de auditoria pericial pública do **Trace Hub**.

**Mantenedor:** Trace Hub Tec Inova Simples (I.S.) — CNPJ 67.302.275/0001-50
**Site:** https://www.trace-hub.com
**Página de auditoria:** https://www.trace-hub.com/auditoria-publica
**Verificador público de evidências:** https://www.trace-hub.com/verificar-evidencia

---

## Para que serve

Este repositório publica, sob a licença [BUSL 1.1](./LICENSE) (com *Change Date* de 4 anos para Apache 2.0), os **módulos críticos** do Trace Hub responsáveis por:

- Cálculo e verificação de hashes forenses (SHA-256)
- Verificação de carimbos de tempo **RFC 3161** e **OpenTimestamps** (Bitcoin)
- Aplicação de carimbo **PAdES** em PDF
- Selagem de sessões de captura (append-only, hash encadeado)
- Ancoragem multi-chain (OriginStamp)
- Prova de integridade de rede (DNS/TLS)
- Cadeia de custódia e laudos
- Validador determinístico de áudio WhatsApp (Opus/OGG)

O escopo completo do que é (e do que **não** é) publicado está em [`MANIFEST.md`](./MANIFEST.md).

## Para quem

- **Peritos** independentes que precisam reproduzir o cálculo do `evidence_hash`, validar TSR/OTS, ou verificar a admissibilidade técnica de uma evidência produzida pelo Trace Hub.
- **Advogados** e **juízes** que precisam de transparência sobre os algoritmos por trás de um laudo.
- **Pesquisadores** de segurança e auditoria interessados em reportar vulnerabilidades.

## Como verificar a integridade deste repositório

Cada arquivo do repo possui hash SHA-256 listado em [`REPO_FILE_HASHES.sha256.txt`](./REPO_FILE_HASHES.sha256.txt). O próprio manifesto está hashado em [`MANIFEST.sha256`](./MANIFEST.sha256).

```bash
# Verificar todos os arquivos
sha256sum -c REPO_FILE_HASHES.sha256.txt

# Verificar o manifesto
sha256sum -c MANIFEST.sha256
```

Em Windows (PowerShell):

```powershell
Get-FileHash <arquivo> -Algorithm SHA256
```

## Como verificar uma evidência produzida pelo Trace Hub

1. Abra https://www.trace-hub.com/verificar-evidencia
2. Faça upload do arquivo ou cole o `evidence_hash` SHA-256.
3. O verificador recalcula o hash, valida o carimbo RFC 3161 e o `.ots` (OpenTimestamps / Bitcoin) **de forma independente** dos servidores do Trace Hub.

Para verificação 100% offline, use as CLIs públicas:

```bash
sha256sum arquivo.pdf
openssl ts -verify -data arquivo.pdf -in arquivo.tsr -CAfile freetsa-ca.pem
ots verify arquivo.ots
```

## O que NÃO está aqui (intencional)

Para preservar a verossimilhança operacional do produto e proteger usuários, **não** publicamos:

- Templates de captura (Instagram, Google, Uber, iFood, etc.)
- Lógica de cloaking e bridge pages
- Painel admin
- Regras CSAM (hashsets, keywords leet, ensemble perceptual)
- Integrações de pagamento
- Notificações Telegram/Push
- Geolocalização ativa (ConsentCapturePage)
- Fingerprinting passivo / Anti-Spy
- Edge Function `notarial-capture` (módulo proprietário)

Lista completa em [`MANIFEST.md`](./MANIFEST.md#o-que-não-é-publicado).

## Reporte de vulnerabilidades

- **E-mail:** `security@trace-hub.com` (PGP disponível mediante solicitação)
- **Auditoria formal com NDA:** `auditoria@trace-hub.com`

Não abra issue pública para vulnerabilidades — siga *responsible disclosure*.

## Licença

[Business Source License 1.1](./LICENSE), convertendo automaticamente para **Apache 2.0** após 4 anos de cada release. Uso para auditoria pericial, pesquisa acadêmica e revisão judicial é **livre e irrestrito** durante todo o período BUSL.

---

© 2024–2026 Trace Hub Tec Inova Simples (I.S.)

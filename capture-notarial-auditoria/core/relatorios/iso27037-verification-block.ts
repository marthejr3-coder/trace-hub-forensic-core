/**
 * ISO/IEC 27037 — Bloco de Verificação por Perito Adversário
 * ============================================================
 * Renderiza, para qualquer laudo digital (Ata Notarial, Selo Premium,
 * Capture Link, Evidence Cripto), o bloco padronizado que satisfaz os
 * três pilares da norma:
 *
 *   • Auditabilidade — o método aplicado está documentado passo a passo.
 *   • Repetibilidade — mesmos comandos + mesmos arquivos = mesmo resultado
 *     em qualquer momento futuro.
 *   • Reprodutibilidade — instrumentos diferentes (nodes Bitcoin, mempool.space,
 *     blockstream.info, Bitcoin Core local) produzem o mesmo veredito.
 *
 * A prova OpenTimestamps ancora no HEADER do bloco Bitcoin (merkle_root do
 * bloco). O TXID da transação agregadora é IRRELEVANTE — o que atesta a
 * existência prévia é o bloco. Este helper materializa esse fato.
 */

export interface Iso27037ProofData {
  /** SHA-256 hex (64 chars) da evidência que foi carimbada. */
  evidenceHash: string;
  /** SHA-256 hex do próprio arquivo .ots entregue (garante integridade do artefato de prova). */
  otsSha256?: string | null;
  /** Altura do bloco Bitcoin em que o .ots foi agregado (via OpenTimestamps). */
  blockHeight?: number | null;
  /** Hash do bloco Bitcoin (64 hex). Independente de TXID; obtido em explorer público. */
  blockHash?: string | null;
  /** Merkle root do header do bloco. É este valor que o .ots reconstitui. */
  blockMerkleRoot?: string | null;
  /** Timestamp Unix (ISO string) do header do bloco Bitcoin. */
  blockTime?: string | null;
  /** Calendários OpenTimestamps utilizados na submissão. */
  calendars?: string[];
  /** Nome do arquivo .ots referenciado no laudo (ex: 'evidence.ots'). */
  otsFilename?: string;
}

const DEFAULT_CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://alice.btc.calendar.opentimestamps.org",
];

/**
 * Devolve as linhas [rótulo, valor] para renderizar em tabelas de laudo
 * (jsPDF autoTable / kv()). São 4 blocos lógicos concatenados.
 */
export function buildIso27037PdfRows(proof: Iso27037ProofData): [string, string][] {
  const cals = proof.calendars?.length ? proof.calendars : DEFAULT_CALENDARS;
  const otsFile = proof.otsFilename || "evidence.ots";
  const height = proof.blockHeight != null ? String(proof.blockHeight) : null;
  const blockHash = proof.blockHash || null;

  const rows: [string, string][] = [];

  // — Auditabilidade —
  rows.push(["--- AUDITABILIDADE (ISO 27037 §5) ---", ""]);
  rows.push(["Método", "OpenTimestamps + RFC 3161 (FreeTSA)"]);
  rows.push(["Biblioteca", "opentimestamps 0.4.9 (JS/Deno) — spec: opentimestamps.org"]);
  rows.push(["Calendários OTS", cals.join("  |  ")]);
  rows.push([
    "Artefato de prova",
    proof.otsSha256 ? `${otsFile} (SHA-256: ${proof.otsSha256})` : `${otsFile} (SHA-256 será calculado ao gerar o .ots)`,
  ]);
  rows.push(["Hash evidência ancorado", proof.evidenceHash]);

  // — Repetibilidade —
  rows.push(["--- REPETIBILIDADE (ISO 27037 §5) ---", ""]);
  rows.push([
    "Idempotência",
    "A prova Merkle contida no .ots é imutável. Reexecutar 'ots verify' a qualquer tempo produz o mesmo bloco.",
  ]);
  rows.push([
    "Comando de re-verificação",
    `ots verify ${otsFile} -d ${proof.evidenceHash}`,
  ]);

  // — Reprodutibilidade —
  rows.push(["--- REPRODUTIBILIDADE (ISO 27037 §5) ---", ""]);
  rows.push([
    "Instrumento 1 — Bitcoin Core (offline)",
    height
      ? `bitcoin-cli getblockhash ${height}   →   ${blockHash || "<hash>"}`
      : "Aguardando altura de bloco",
  ]);
  rows.push([
    "Instrumento 2 — mempool.space",
    height
      ? `https://mempool.space/block/${height}`
      : "https://mempool.space (buscar por bloco após confirmação)",
  ]);
  rows.push([
    "Instrumento 3 — blockstream.info",
    height
      ? `https://blockstream.info/block/${height}`
      : "https://blockstream.info (buscar por bloco após confirmação)",
  ]);
  rows.push([
    "Confronto esperado",
    "Os 3 instrumentos devem devolver EXATAMENTE o mesmo block_hash e merkle_root — divergência invalida a prova.",
  ]);
  if (blockHash) rows.push(["Block hash esperado", blockHash]);
  if (proof.blockMerkleRoot) rows.push(["Merkle root esperado", proof.blockMerkleRoot]);
  if (proof.blockTime) rows.push(["Block time (UTC)", proof.blockTime]);

  // — Comandos de perícia (passo a passo) —
  rows.push(["--- COMANDOS DE PERÍCIA (passo a passo) ---", ""]);
  rows.push(["1. Inspecionar .ots", `ots info ${otsFile}`]);
  rows.push(["2. Verificar contra hash", `ots verify ${otsFile} -d ${proof.evidenceHash}`]);
  rows.push([
    "3. Confirmar bloco em node local",
    height ? `bitcoin-cli getblockheader $(bitcoin-cli getblockhash ${height})` : "(após confirmação)",
  ]);
  rows.push([
    "4. Confirmar bloco em explorer público",
    height ? `curl https://mempool.space/api/block-height/${height}` : "(após confirmação)",
  ]);
  rows.push([
    "Nota sobre TXID",
    "A prova OpenTimestamps ancora no HEADER do bloco (merkle_root). O TXID da transação agregadora é irrelevante — o que garante anterioridade é o bloco Bitcoin, não a transação individual.",
  ]);

  return rows;
}

/**
 * Devolve o mesmo bloco em texto puro, para embarque em README.txt do ZIP
 * forense (Evidence Cripto, Capture Link).
 */
export function buildIso27037TextBlock(proof: Iso27037ProofData): string {
  const cals = proof.calendars?.length ? proof.calendars : DEFAULT_CALENDARS;
  const otsFile = proof.otsFilename || "evidence.ots";
  const height = proof.blockHeight != null ? String(proof.blockHeight) : "<aguardando>";
  const blockHash = proof.blockHash || "<aguardando>";
  const merkle = proof.blockMerkleRoot || "<aguardando>";
  const blockTime = proof.blockTime || "<aguardando>";

  return [
    "VERIFICAÇÃO INDEPENDENTE — ISO/IEC 27037",
    "=".repeat(70),
    "",
    "Este documento permite ao PERITO ADVERSÁRIO confirmar, sem depender",
    "do Trace Hub e sem depender de TXID, que a evidência foi ancorada em",
    "um bloco Bitcoin específico — satisfazendo os pilares de",
    "AUDITABILIDADE, REPETIBILIDADE e REPRODUTIBILIDADE da ISO 27037.",
    "",
    "─".repeat(70),
    "1) AUDITABILIDADE",
    "─".repeat(70),
    `  Método            : OpenTimestamps + RFC 3161 (FreeTSA)`,
    `  Biblioteca        : opentimestamps 0.4.9 (spec pública em opentimestamps.org)`,
    `  Calendários OTS   :`,
    ...cals.map((c) => `    - ${c}`),
    `  Artefato de prova : ${otsFile}`,
    `  SHA-256 do .ots   : ${proof.otsSha256 || "<não fornecido>"}`,
    `  Hash ancorado     : ${proof.evidenceHash}`,
    "",
    "─".repeat(70),
    "2) REPETIBILIDADE",
    "─".repeat(70),
    "  A prova Merkle contida no .ots é imutável e idempotente. Executar",
    "  o mesmo comando em qualquer computador, em qualquer momento futuro,",
    "  produz o mesmo resultado — este é o teste de repetibilidade.",
    "",
    `    $ ots verify ${otsFile} -d ${proof.evidenceHash}`,
    "",
    "─".repeat(70),
    "3) REPRODUTIBILIDADE",
    "─".repeat(70),
    "  Três instrumentos INDEPENDENTES devem devolver o mesmo bloco.",
    "  Qualquer divergência invalida a prova.",
    "",
    "  Instrumento 1 — Bitcoin Core (node local, offline):",
    `    $ bitcoin-cli getblockhash ${height}`,
    `      → esperado: ${blockHash}`,
    `    $ bitcoin-cli getblockheader ${blockHash}`,
    `      → merkleroot esperado: ${merkle}`,
    `      → time esperado (UTC): ${blockTime}`,
    "",
    "  Instrumento 2 — mempool.space (explorer público):",
    `    $ curl https://mempool.space/api/block-height/${height}`,
    `      → deve devolver: ${blockHash}`,
    "",
    "  Instrumento 3 — blockstream.info (explorer público independente):",
    `    $ curl https://blockstream.info/api/block-height/${height}`,
    `      → deve devolver: ${blockHash}`,
    "",
    "─".repeat(70),
    "4) COMANDOS DE PERÍCIA (roteiro completo)",
    "─".repeat(70),
    `  # 1. Inspecionar a árvore Merkle do .ots`,
    `  $ ots info ${otsFile}`,
    "",
    `  # 2. Verificar que o hash da evidência gera a raiz esperada`,
    `  $ ots verify ${otsFile} -d ${proof.evidenceHash}`,
    "",
    `  # 3. Confirmar o bloco Bitcoin em um node local (opcional, offline)`,
    `  $ bitcoin-cli getblockheader $(bitcoin-cli getblockhash ${height})`,
    "",
    `  # 4. Confirmar o mesmo bloco em explorers públicos independentes`,
    `  $ curl https://mempool.space/api/block-height/${height}`,
    `  $ curl https://blockstream.info/api/block-height/${height}`,
    "",
    "─".repeat(70),
    "NOTA JURÍDICA — Por que não há TXID?",
    "─".repeat(70),
    "  A prova OpenTimestamps não é uma transação Bitcoin individual: é",
    "  uma árvore de Merkle cuja raiz é publicada no OP_RETURN de uma",
    "  transação agregadora, e cujo topo COINCIDE com o merkle_root do",
    "  HEADER do bloco Bitcoin. Portanto, a âncora de anterioridade é o",
    "  BLOCO, não a transação. Este é o comportamento previsto na",
    "  especificação OpenTimestamps (opentimestamps.org) e na BIP-141.",
    "  Explorers públicos e nodes Bitcoin locais reproduzem a verificação",
    "  a partir do block_hash + block_height acima.",
    "",
  ].join("\n");
}

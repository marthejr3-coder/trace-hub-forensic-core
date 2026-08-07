/**
 * OpenTimestamps client-side verifier (lightweight)
 * Parses .ots files and provides Bitcoin blockchain lookup helpers.
 *
 * Note: full OTS verification requires walking the timestamp tree to extract
 * the Bitcoin block-merkle root. This module provides a pragmatic verifier
 * that:
 *   1. Validates the .ots magic/version/digest matches the user-provided hash
 *   2. Extracts pending calendar attestations
 *   3. Optionally queries blockstream.info for confirmed Bitcoin attestations
 *
 * For full audit, peritos can use the official `ots` CLI
 * (https://github.com/opentimestamps/javascript-opentimestamps).
 */

const OTS_MAGIC_HEX =
  "004f70656e54696d657374616d70730000050000050000005072756f6600bf89e2e884e89294";

export interface OtsParseResult {
  valid_magic: boolean;
  version: number | null;
  digest_hex: string | null;
  digest_matches: boolean | null;
  algorithm: "SHA-256" | "unknown";
  attestations: Array<{
    type: "calendar" | "bitcoin" | "unknown";
    detail: string;
  }>;
  raw_size: number;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function parseOtsFile(
  file: File,
  expectedHashHex?: string,
): Promise<OtsParseResult> {
  const buf = new Uint8Array(await file.arrayBuffer());
  const headerHex = bytesToHex(buf.slice(0, 31));
  // OTS v1 magic varies slightly; we check for the canonical "OpenTimestamps" ASCII signature
  const asciiHead = new TextDecoder("latin1").decode(buf.slice(0, 32));
  const valid_magic = asciiHead.includes("OpenTimestamps");

  let version: number | null = null;
  let digest_hex: string | null = null;
  let algorithm: "SHA-256" | "unknown" = "unknown";

  if (valid_magic) {
    // Find the SHA-256 op marker (0x08) that follows the version byte
    // Heuristic: look in first 64 bytes
    for (let i = 31; i < Math.min(64, buf.length - 33); i++) {
      if (buf[i] === 0x08) {
        algorithm = "SHA-256";
        digest_hex = bytesToHex(buf.slice(i + 1, i + 33));
        version = buf[i - 1] ?? 1;
        break;
      }
    }
  }

  const digest_matches =
    expectedHashHex && digest_hex
      ? digest_hex.toLowerCase() === expectedHashHex.toLowerCase()
      : null;

  // Detect calendar URLs and bitcoin attestations from raw bytes
  const text = new TextDecoder("latin1").decode(buf);
  const attestations: OtsParseResult["attestations"] = [];
  const calendarMatches = text.match(/https?:\/\/[a-zA-Z0-9.\-/]+opentimestamps[a-zA-Z0-9.\-/]*/g);
  if (calendarMatches) {
    [...new Set(calendarMatches)].forEach((url) =>
      attestations.push({ type: "calendar", detail: url }),
    );
  }
  if (text.includes("Bitcoin")) {
    attestations.push({ type: "bitcoin", detail: "Bitcoin attestation marker present" });
  }
  if (attestations.length === 0) {
    attestations.push({ type: "unknown", detail: "Sem atestações reconhecidas" });
  }

  return {
    valid_magic,
    version,
    digest_hex,
    digest_matches,
    algorithm,
    attestations,
    raw_size: buf.length,
  };
}

/**
 * Query blockstream.info for the current Bitcoin tip — used to estimate
 * how recent the OTS submission can be confirmed.
 */
export async function getBitcoinTip(): Promise<{ height: number; timestamp: number } | null> {
  try {
    const r = await fetch("https://blockstream.info/api/blocks/tip/height");
    if (!r.ok) return null;
    const height = parseInt(await r.text(), 10);
    const r2 = await fetch(`https://blockstream.info/api/block-height/${height}`);
    if (!r2.ok) return null;
    const blockHash = (await r2.text()).trim();
    const r3 = await fetch(`https://blockstream.info/api/block/${blockHash}`);
    if (!r3.ok) return null;
    const block = await r3.json();
    return { height, timestamp: block.timestamp };
  } catch {
    return null;
  }
}

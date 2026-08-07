import { afterEach, describe, expect, it, vi } from "vitest";
import { SealedRecordingStore } from "./sealed-recording-store";

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

describe("SealedRecordingStore", () => {
  const originalIndexedDb = globalThis.indexedDB;

  afterEach(() => {
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: originalIndexedDb });
    vi.restoreAllMocks();
  });

  it("preserva a ordem dos chunks e produz o SHA-256 dos bytes finais", async () => {
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
    const first = new Uint8Array([0, 1, 2, 3, 4]);
    const second = new Uint8Array([250, 251, 252, 253]);
    const expectedBytes = new Uint8Array([...first, ...second]);
    const expectedHash = toHex(await crypto.subtle.digest("SHA-256", expectedBytes));
    const store = new SealedRecordingStore("test-session", "video/webm", "webm");

    expect(await store.initialize()).toBe("memory");
    store.append(new Blob([first]));
    store.append(new Blob([second]));

    const result = await store.finalize();
    expect(result).not.toBeNull();
    if (!result) throw new Error("A gravação temporária não foi finalizada");
    expect(result?.sha256).toBe(expectedHash);
    expect(result?.size).toBe(expectedBytes.byteLength);
    expect(new Uint8Array(await result.file.arrayBuffer())).toEqual(expectedBytes);

    await store.discard();
  });

  it("devolve o mesmo resultado quando a finalização é chamada novamente", async () => {
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
    const store = new SealedRecordingStore("dedupe-session", "video/webm", "webm");
    await store.initialize();
    store.append(new Blob([new Uint8Array([7, 8, 9])]));

    const first = await store.finalize();
    const second = await store.finalize();
    expect(second).toBe(first);
  });

  it("expõe e drena os bytes pendentes sem alterar a ordem", async () => {
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
    const store = new SealedRecordingStore("backpressure-session", "video/webm", "webm");
    await store.initialize();
    const chunk = new Blob([new Uint8Array(1024 * 1024)]);

    const pending = store.append(chunk);
    expect(store.pendingBytes).toBe(chunk.size);
    await pending;
    await store.drain();
    expect(store.pendingBytes).toBe(0);

    const result = await store.finalize();
    expect(result?.size).toBe(chunk.size);
  });

  it("interrompe o fallback em memória antes de consumir a aba", async () => {
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
    const store = new SealedRecordingStore("memory-limit-session", "video/webm", "webm");
    await store.initialize();
    const oversized = new Blob([new Uint8Array(65 * 1024 * 1024)]);

    await expect(store.append(oversized)).rejects.toThrow("limite seguro de 64 MB");
    await expect(store.drain()).rejects.toThrow("limite seguro de 64 MB");
  });
});
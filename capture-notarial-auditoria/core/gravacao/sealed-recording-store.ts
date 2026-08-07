import { createSHA256 } from "hash-wasm";

const MEMORY_FALLBACK_LIMIT = 64 * 1024 * 1024;
const TEMP_PREFIX = "sealed-recording-";
const ABANDONED_AFTER_MS = 24 * 60 * 60 * 1000;
const MIN_RECOMMENDED_FREE_BYTES = 512 * 1024 * 1024;

type Backend = "opfs" | "memory";

export type SealedRecordingResult = {
  file: File;
  sha256: string;
  size: number;
  backend: Backend;
};

function hasOpfs(): boolean {
  return typeof navigator !== "undefined" && typeof navigator.storage?.getDirectory === "function";
}

export class SealedRecordingStore {
  private readonly recordingId: string;
  private readonly fileName: string;
  private readonly mime: string;
  private backend: Backend = "memory";
  private writable: FileSystemWritableFileStream | null = null;
  private root: FileSystemDirectoryHandle | null = null;
  private memoryChunks: Blob[] = [];
  private queue: Promise<void> = Promise.resolve();
  private hasher: Awaited<ReturnType<typeof createSHA256>> | null = null;
  private byteLength = 0;
  private pendingByteLength = 0;
  private finalized: SealedRecordingResult | null = null;
  private writeError: Error | null = null;

  constructor(recordingId: string, mime: string, extension: string) {
    this.recordingId = recordingId;
    this.mime = mime;
    this.fileName = `${TEMP_PREFIX}${Date.now()}-${recordingId}.${extension}`;
  }

  async initialize(): Promise<Backend> {
    this.hasher = await createSHA256();
    this.hasher.init();

    if (hasOpfs()) {
      try {
        await navigator.storage.persist?.().catch(() => false);
        const estimate = await navigator.storage.estimate?.();
        if (estimate?.quota != null && estimate.usage != null) {
          const available = Math.max(0, estimate.quota - estimate.usage);
          if (available < MIN_RECOMMENDED_FREE_BYTES) {
            throw new Error(
              `Espaço temporário insuficiente para uma gravação segura (${Math.floor(available / 1024 / 1024)} MB livres).`,
            );
          }
        }
        this.root = await navigator.storage.getDirectory();
        const handle = await this.root.getFileHandle(this.fileName, { create: true });
        this.writable = await handle.createWritable({ keepExistingData: false });
        this.backend = "opfs";
        return this.backend;
      } catch (error) {
        if (error instanceof Error && error.message.includes("Espaço temporário insuficiente")) throw error;
        console.warn("sealed recording: OPFS indisponível, usando contingência", error);
      }
    }

    this.backend = "memory";
    return this.backend;
  }

  append(chunk: Blob): Promise<void> {
    if (!chunk.size || this.finalized) return Promise.resolve();
    if (this.writeError) return Promise.reject(this.writeError);
    this.byteLength += chunk.size;
    this.pendingByteLength += chunk.size;
    const operation = this.queue
      .then(async () => {
        const bytes = new Uint8Array(await chunk.arrayBuffer());
        this.hasher?.update(bytes);
        if (this.backend === "opfs") {
          if (!this.writable) throw new Error("Arquivo temporário da gravação foi fechado antes da hora");
          await this.writable.write(chunk);
          return;
        }
        if (this.byteLength > MEMORY_FALLBACK_LIMIT) {
          throw new Error("O navegador não ofereceu armazenamento temporário em disco e atingiu o limite seguro de 64 MB.");
        }
        this.memoryChunks.push(chunk);
      })
      .finally(() => {
        this.pendingByteLength = Math.max(0, this.pendingByteLength - chunk.size);
      });
    this.queue = operation
      .catch((error) => {
        this.writeError = error instanceof Error ? error : new Error(String(error));
      });
    return operation;
  }

  get pendingBytes(): number {
    return this.pendingByteLength;
  }

  async drain(): Promise<void> {
    await this.queue;
    if (this.writeError) throw this.writeError;
  }

  async finalize(): Promise<SealedRecordingResult | null> {
    if (this.finalized) return this.finalized;
    await this.queue;
    if (this.writeError) throw this.writeError;
    if (this.byteLength === 0 || !this.hasher) return null;

    let file: File;
    if (this.backend === "opfs") {
      await this.writable?.close();
      this.writable = null;
      const handle = await this.root?.getFileHandle(this.fileName);
      if (!handle) throw new Error("Arquivo temporário da gravação não foi localizado");
      file = await handle.getFile();
    } else {
      file = new File(this.memoryChunks, this.fileName, { type: this.mime, lastModified: Date.now() });
      this.memoryChunks = [];
    }

    this.finalized = {
      file,
      sha256: this.hasher.digest("hex"),
      size: this.byteLength,
      backend: this.backend,
    };
    return this.finalized;
  }

  async discard(): Promise<void> {
    await this.queue;
    try {
      await this.writable?.abort();
    } catch {
      /* already closed */
    }
    this.writable = null;
    this.memoryChunks = [];
    this.finalized = null;
    if (this.backend === "opfs" && this.root) {
      try {
        await this.root.removeEntry(this.fileName);
      } catch {
        /* already removed */
      }
    }
  }
}

export async function cleanupAbandonedSealedRecordings(): Promise<void> {
  if (!hasOpfs()) return;
  try {
    const root = await navigator.storage.getDirectory();
    const entries = (root as FileSystemDirectoryHandle & {
      entries: () => AsyncIterableIterator<[string, FileSystemHandle]>;
    }).entries();
    const now = Date.now();
    for await (const [name] of entries) {
      if (!name.startsWith(TEMP_PREFIX)) continue;
      const timestamp = Number(name.slice(TEMP_PREFIX.length).split("-")[0]);
      if (Number.isFinite(timestamp) && now - timestamp > ABANDONED_AFTER_MS) {
        await root.removeEntry(name).catch(() => undefined);
      }
    }
  } catch {
    /* limpeza oportunista */
  }
}
import * as tus from "tus-js-client";
import { supabase } from "@/integrations/supabase/client";

const CHUNK_SIZE = 6 * 1024 * 1024;

export type ResumableUploadResult = {
  path: string;
  signedUrl: string | null;
  expiresAt: string;
};

export async function uploadSealedVideoResumable(options: {
  file: File;
  path: string;
  contentType: string;
  onProgress?: (uploaded: number, total: number) => void;
}): Promise<ResumableUploadResult> {
  const { data, error } = await supabase.auth.getSession();
  if (error || !data.session?.access_token) throw error ?? new Error("Sessão expirada");

  const endpoint = `${import.meta.env.VITE_SUPABASE_URL}/storage/v1/upload/resumable`;
  const upload = new tus.Upload(options.file, {
    endpoint,
    chunkSize: CHUNK_SIZE,
    retryDelays: [0, 1_000, 3_000, 5_000, 10_000],
    removeFingerprintOnSuccess: true,
    uploadDataDuringCreation: true,
    headers: {
      authorization: `Bearer ${data.session.access_token}`,
      apikey: import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
      "x-upsert": "false",
    },
    metadata: {
      bucketName: "sealed-capture",
      objectName: options.path,
      contentType: options.contentType,
      cacheControl: "3600",
    },
    onProgress: options.onProgress,
  });

  await new Promise<void>((resolve, reject) => {
    upload.options.onError = reject;
    upload.options.onSuccess = () => resolve();
    void upload.findPreviousUploads().then((previous) => {
      const candidate = previous[0];
      if (candidate) upload.resumeFromPreviousUpload(candidate);
      upload.start();
    }).catch(reject);
  });

  const ttl = 60 * 60 * 24 * 30;
  const { data: signed, error: signedError } = await supabase.storage
    .from("sealed-capture")
    .createSignedUrl(options.path, ttl);
  if (signedError) throw signedError;
  return {
    path: options.path,
    signedUrl: signed?.signedUrl ?? null,
    expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
  };
}
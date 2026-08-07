export class DisplayAudioCompatibilityError extends Error {
  constructor() {
    super("Este navegador não conseguiu iniciar uma captura compatível com áudio. Atualize o Chrome/Edge e tente novamente escolhendo uma Aba do navegador.");
    this.name = "DisplayAudioCompatibilityError";
  }
}

type DisplayMediaDevices = Pick<MediaDevices, "getDisplayMedia">;

/**
 * Solicita a superfície com áudio e preserva o áudio no fallback usado quando
 * o navegador rejeita as opções avançadas de captura.
 */
export async function requestDisplayMediaWithAudio(mediaDevices: DisplayMediaDevices): Promise<MediaStream> {
  const enhancedConstraints = {
    video: true,
    audio: {
      echoCancellation: false,
      noiseSuppression: false,
      autoGainControl: false,
      suppressLocalAudioPlayback: false,
    },
    selfBrowserSurface: "exclude",
    surfaceSwitching: "include",
    systemAudio: "include",
  } as unknown as DisplayMediaStreamOptions;

  try {
    return await mediaDevices.getDisplayMedia(enhancedConstraints);
  } catch (error) {
    const name = (error as { name?: string } | null)?.name;
    if (name !== "NotSupportedError" && name !== "TypeError") throw error;

    try {
      // Nunca degradar para `video: true`: isso desativa a trilha mesmo quando
      // o operador marca “Compartilhar áudio da aba” no seletor.
      return await mediaDevices.getDisplayMedia({ video: true, audio: true });
    } catch (fallbackError) {
      const fallbackName = (fallbackError as { name?: string } | null)?.name;
      if (fallbackName === "NotSupportedError" || fallbackName === "TypeError") {
        throw new DisplayAudioCompatibilityError();
      }
      throw fallbackError;
    }
  }
}
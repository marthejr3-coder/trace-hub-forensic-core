import { describe, expect, it, vi } from 'vitest';
import { hashFileSHA256 } from './file-hash-stream';

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

describe('hashFileSHA256', () => {
  it('produz o mesmo SHA-256 da Web Crypto lendo em fatias', async () => {
    const bytes = new Uint8Array(9 * 1024 * 1024 + 137);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = index % 251;
    const blob = new Blob([bytes]);
    const progress = vi.fn();

    const expected = toHex(await crypto.subtle.digest('SHA-256', bytes));
    const actual = await hashFileSHA256(blob, progress);

    expect(actual).toBe(expected);
    expect(progress).toHaveBeenCalled();
    expect(progress).toHaveBeenLastCalledWith(blob.size, blob.size);
  });
});
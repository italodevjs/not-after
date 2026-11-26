import { open } from "node:fs/promises";
import { MAX_INPUT_BYTES } from "./model";
export async function readBoundedCertificate(
  path: string,
): Promise<ArrayBuffer> {
  const handle = await open(path, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile())
      throw new Error("Input must be a regular certificate file.");
    if (stat.size > MAX_INPUT_BYTES)
      throw new Error("File exceeds the 1 MiB limit.");
    const buffer = Buffer.alloc(MAX_INPUT_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        total,
        buffer.length - total,
        null,
      );
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total > MAX_INPUT_BYTES)
      throw new Error("File exceeds the 1 MiB limit.");
    return new Uint8Array(buffer.subarray(0, total)).buffer;
  } finally {
    await handle.close();
  }
}

import { mkdtemp, writeFile, unlink, rmdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
import { readBoundedCertificate } from "../src/files";
it("reads small regular files and rejects oversized files before allocating their content", async () => {
  const directory = await mkdtemp(join(tmpdir(), "not-after-"));
  const small = join(directory, "small.pem"),
    large = join(directory, "large.pem");
  try {
    await writeFile(small, "fixture");
    await writeFile(large, Buffer.alloc(1024 * 1024 + 1));
    expect(new TextDecoder().decode(await readBoundedCertificate(small))).toBe(
      "fixture",
    );
    await expect(readBoundedCertificate(large)).rejects.toThrow("1 MiB");
  } finally {
    await unlink(small);
    await unlink(large);
    await rmdir(directory);
  }
});

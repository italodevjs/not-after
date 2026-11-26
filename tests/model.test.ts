import "reflect-metadata";
import { readFile } from "node:fs/promises";
import { X509CertificateGenerator } from "@peculiar/x509";
import { X509Certificate as NodeCertificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  certificateBlocks,
  createReport,
  csvReport,
  evaluateWindow,
  inspectBytes,
  inspectText,
  mergeCertificates,
  parseEvaluationTimestamp,
  type CertificateRecord,
} from "../src/model";
import {
  persistCertificates,
  restoreCertificates,
  STORAGE_KEY,
} from "../src/storage";
const bundle = await readFile(
  new URL("../public/examples/certificates.pem", import.meta.url),
  "utf8",
);
const examples = await inspectText(bundle, "Example certificate");
const current = examples[1]!;

describe("real X.509 import", () => {
  it("parses a three-certificate PEM bundle and matches independent Node/OpenSSL metadata", () => {
    expect(examples).toHaveLength(3);
    for (const cert of examples) {
      const independent = new NodeCertificate(cert.pem);
      expect(cert.fingerprint).toBe(independent.fingerprint256);
      expect(cert.notBefore).toBe(
        new Date(independent.validFrom).toISOString(),
      );
      expect(cert.notAfter).toBe(new Date(independent.validTo).toISOString());
      expect(cert.subject).toContain(".example.test");
      expect(cert.dnsNames[0]).toContain(".example.test");
    }
  });
  it("parses DER bytes using the same model", async () => {
    const independent = new NodeCertificate(current.pem);
    const bytes = new Uint8Array(independent.raw).buffer;
    expect((await inspectBytes(bytes, "public.cer"))[0]?.fingerprint).toBe(
      current.fingerprint,
    );
  });
  it("rejects private keys, requests, containers, malformed and mixed bundles", async () => {
    expect(() =>
      certificateBlocks(
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
      ),
    ).toThrow("Only public");
    expect(() =>
      certificateBlocks(bundle + "\n-----BEGIN RSA PRIVATE KEY-----"),
    ).toThrow("Only public");
    expect(() => certificateBlocks(bundle + "\nextra")).toThrow(
      "Unexpected content",
    );
    await expect(
      inspectText(
        current.pem +
          "\n-----BEGIN CERTIFICATE-----\nBAD\n-----END CERTIFICATE-----",
      ),
    ).rejects.toThrow();
    await expect(
      inspectBytes(new Uint8Array([1, 2, 3]).buffer, "secret.p12"),
    ).rejects.toThrow("Private-key");
    await expect(
      inspectText(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
      ),
    ).rejects.toThrow("not a supported");
  });
  it("limits input size and certificate count before parsing", () => {
    expect(() => certificateBlocks("a".repeat(1024 * 1024 + 1))).toThrow(
      "1 MiB",
    );
    expect(() =>
      certificateBlocks(Array(65).fill(current.pem).join("\n")),
    ).toThrow("64 certificates");
  });
  it("rejects an actual certificate with an inverted validity window before it enters the register", async () => {
    const keys = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    const invalid = await X509CertificateGenerator.createSelfSigned({
      name: "CN=inverted.example.test",
      serialNumber: "04",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      notBefore: new Date("2030-01-01T00:00:00Z"),
      notAfter: new Date("2020-01-01T00:00:00Z"),
    });
    await expect(inspectText(invalid.toString("pem"))).rejects.toThrow(
      "inverted",
    );
  });
  it("deduplicates on DER fingerprint and preserves stable expiry ordering", async () => {
    const alternate = current.pem.replaceAll("\r\n", "\n");
    const same = await inspectText(alternate, "Another filename");
    const result = mergeCertificates(examples, same);
    expect(result).toHaveLength(3);
    expect(result.map((c) => c.notAfter)).toEqual(
      [...examples.map((c) => c.notAfter)].sort(),
    );
    expect(
      result.find((c) => c.fingerprint === current.fingerprint)?.source,
    ).toBe("Example certificate");
  });
});

describe("inclusive validity boundaries in UTC", () => {
  const cert = {
    notBefore: "2030-01-01T00:00:00.000Z",
    notAfter: "2030-02-01T00:00:00.000Z",
  };
  it("distinguishes the instants before, inside, and after the window", () => {
    expect(
      evaluateWindow(cert, new Date("2029-12-31T23:59:59.999Z")).status,
    ).toBe("not-yet-valid");
    expect(evaluateWindow(cert, new Date(cert.notBefore)).status).toBe(
      "in-window",
    );
    expect(evaluateWindow(cert, new Date("2030-01-02T00:00:00Z")).status).toBe(
      "expiring",
    );
    expect(evaluateWindow(cert, new Date(cert.notAfter)).status).toBe(
      "expiring",
    );
    expect(
      evaluateWindow(cert, new Date("2030-02-01T00:00:00.001Z")).status,
    ).toBe("expired");
  });
  it("handles invalid dates and inverted windows as errors", () => {
    expect(() => evaluateWindow(cert, new Date("bad"))).toThrow();
    expect(() =>
      evaluateWindow(
        { ...cert, notBefore: cert.notAfter, notAfter: cert.notBefore },
        new Date(),
      ),
    ).toThrow();
    expect(() => evaluateWindow(cert, new Date(), -1)).toThrow();
  });
  it("requires exact UTC ISO calendar timestamps without normalization", () => {
    expect(parseEvaluationTimestamp("2030-02-01T00:00:00Z").toISOString()).toBe(
      "2030-02-01T00:00:00.000Z",
    );
    expect(
      parseEvaluationTimestamp("2030-02-01T00:00:00.1Z").toISOString(),
    ).toBe("2030-02-01T00:00:00.100Z");
    for (const invalid of [
      "Nov 25 2030Z",
      "2030-02-30T00:00:00Z",
      "2030-01-01T24:00:00Z",
      "2030-01-01T00:00:00+00:00",
    ])
      expect(() => parseEvaluationTimestamp(invalid)).toThrow();
  });
});

describe("report and storage boundaries", () => {
  const at = new Date("2026-11-25T12:00:00Z");
  it("reports reproducible metadata without the original PEM", () => {
    const report = createReport(examples, at);
    expect(report.evaluatedAt).toBe(at.toISOString());
    expect(report.certificates.map((c) => c.status)).toEqual([
      "expired",
      "in-window",
      "not-yet-valid",
    ]);
    expect(report.certificates[0]).not.toHaveProperty("pem");
    expect(report.inspection).toContain("No trust");
  });
  it("quotes CSV cells, line breaks and formula-like content", () => {
    const record: CertificateRecord = {
      ...current,
      subject: '=HYPERLINK("bad")\nnext',
    };
    const csv = csvReport([record], at);
    expect(csv).toContain('"\'=HYPERLINK(""bad"")\nnext"');
    expect(csv).toContain(at.toISOString());
  });
  it("persists only after opt-in and reparses source rather than trusting stored metadata", async () => {
    const data = new Map<string, string>();
    const storage = {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => {
        data.set(key, value);
      },
      removeItem: (key: string) => {
        data.delete(key);
      },
    };
    persistCertificates(storage, examples, false);
    expect(await restoreCertificates(storage)).toBeNull();
    persistCertificates(storage, examples, true);
    expect(
      (await restoreCertificates(storage))?.map((c) => c.fingerprint),
    ).toEqual(examples.map((c) => c.fingerprint));
    data.set(
      STORAGE_KEY,
      JSON.stringify({ version: 1, certificates: ["bad"] }),
    );
    await expect(restoreCertificates(storage)).rejects.toThrow();
    persistCertificates(storage, [], false);
    expect(data.size).toBe(0);
  });
});

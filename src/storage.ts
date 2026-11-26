import {
  inspectText,
  mergeCertificates,
  type CertificateRecord,
} from "./model";
export const STORAGE_KEY = "not-after.certificates.v1";
interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}
export function persistCertificates(
  storage: StorageLike,
  records: CertificateRecord[],
  enabled: boolean,
) {
  if (!enabled) {
    storage.removeItem(STORAGE_KEY);
    return;
  }
  const body = JSON.stringify({
    version: 1,
    certificates: records.map((c) => c.pem),
  });
  if (body.length > 2 * 1024 * 1024)
    throw new Error(
      "Local storage budget exceeded. Export a report or keep this session in memory.",
    );
  storage.setItem(STORAGE_KEY, body);
}
export async function restoreCertificates(
  storage: StorageLike,
): Promise<CertificateRecord[] | null> {
  const value = storage.getItem(STORAGE_KEY);
  if (value === null) return null;
  if (value.length > 2 * 1024 * 1024)
    throw new Error("Saved register exceeds the storage limit.");
  const data: unknown = JSON.parse(value);
  if (
    !data ||
    typeof data !== "object" ||
    !("version" in data) ||
    data.version !== 1 ||
    !("certificates" in data) ||
    !Array.isArray(data.certificates) ||
    data.certificates.length > 256 ||
    data.certificates.some((v) => typeof v !== "string")
  )
    throw new Error("Saved register format is invalid.");
  let records: CertificateRecord[] = [];
  for (const pem of data.certificates as string[])
    records = mergeCertificates(
      records,
      await inspectText(pem, "Saved on this device"),
    );
  return records;
}

import 'reflect-metadata';
import { BasicConstraintsExtension, SubjectAlternativeNameExtension, X509Certificate } from '@peculiar/x509';

export const MAX_INPUT_BYTES = 1024 * 1024;
export const MAX_BUNDLE_CERTIFICATES = 64;
export const MAX_REGISTER_CERTIFICATES = 256;
const DAY = 86_400_000;
export interface CertificateRecord {
  fingerprint: string;
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  publicKeyAlgorithm: string;
  signatureAlgorithm: string;
  dnsNames: string[];
  certificateAuthority: boolean;
  pem: string;
  source: string;
}
export type WindowStatus = 'expired' | 'not-yet-valid' | 'expiring' | 'in-window';
export interface WindowEvaluation { status: WindowStatus; remainingMilliseconds: number; remainingDays: number }

export function evaluateWindow(cert: Pick<CertificateRecord, 'notBefore' | 'notAfter'>, at: Date, warningDays = 30): WindowEvaluation {
  const now = at.getTime(), start = Date.parse(cert.notBefore), end = Date.parse(cert.notAfter);
  if (![now, start, end].every(Number.isFinite) || start > end || !Number.isFinite(warningDays) || warningDays < 0) throw new Error('Invalid certificate window or evaluation time.');
  const remainingMilliseconds = end - now;
  // RFC 5280 includes both notBefore and notAfter instants in the validity interval.
  const status: WindowStatus = now < start ? 'not-yet-valid' : now > end ? 'expired' : remainingMilliseconds <= warningDays * DAY ? 'expiring' : 'in-window';
  return { status, remainingMilliseconds, remainingDays: Math.ceil(remainingMilliseconds / DAY) };
}

export function certificateBlocks(text: string): string[] {
  if (new TextEncoder().encode(text).length > MAX_INPUT_BYTES) throw new Error('Input exceeds the 1 MiB limit.');
  if (/-----BEGIN [^-]*(PRIVATE KEY|PUBLIC KEY|CERTIFICATE REQUEST)/i.test(text)) throw new Error('Only public certificates are accepted. Remove keys and certificate requests.');
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (!blocks.length) throw new Error('No PEM certificates found. Use BEGIN CERTIFICATE blocks or open a DER file.');
  if (blocks.length > MAX_BUNDLE_CERTIFICATES) throw new Error('A bundle may contain at most 64 certificates.');
  const remainder = text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim();
  if (remainder) throw new Error('Unexpected content outside certificate blocks. Paste certificates only.');
  return blocks;
}

async function inspectOne(data: string | ArrayBuffer, source: string): Promise<CertificateRecord> {
  let cert: X509Certificate;
  try { cert = new X509Certificate(data); } catch { throw new Error('This input is not a supported X.509 certificate.'); }
  if (cert.rawData.byteLength > 65536) throw new Error('A single certificate exceeds the 64 KiB limit.');
  const digest = await cert.getThumbprint('SHA-256', globalThis.crypto);
  const fingerprint = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join(':').toUpperCase();
  const names = cert.getExtension(SubjectAlternativeNameExtension)?.names.items ?? [];
  return { fingerprint, subject: cert.subject, issuer: cert.issuer, serial: cert.serialNumber, notBefore: cert.notBefore.toISOString(), notAfter: cert.notAfter.toISOString(), publicKeyAlgorithm: cert.publicKey.algorithm.name, signatureAlgorithm: cert.signatureAlgorithm.name, dnsNames: names.filter(n => n.type === 'dns').map(n => String(n.value)), certificateAuthority: cert.getExtension(BasicConstraintsExtension)?.ca ?? false, pem: cert.toString('pem'), source: source.slice(0, 200) };
}

export async function inspectText(text: string, source = 'Pasted certificate'): Promise<CertificateRecord[]> {
  const blocks = certificateBlocks(text);
  // All-or-nothing import: no half-populated register on a malformed bundle.
  const result: CertificateRecord[] = [];
  for (const block of blocks) result.push(await inspectOne(block, source));
  return result;
}

export async function inspectBytes(bytes: ArrayBuffer, source: string): Promise<CertificateRecord[]> {
  if (!bytes.byteLength || bytes.byteLength > MAX_INPUT_BYTES) throw new Error('File must contain between 1 byte and 1 MiB.');
  if (/\.(pfx|p12|key)$/i.test(source)) throw new Error('Private-key containers are not accepted. Use a public PEM or DER certificate.');
  const text = new TextDecoder().decode(bytes);
  if (text.includes('-----BEGIN')) return inspectText(text, source);
  return [await inspectOne(bytes, source)];
}

export function mergeCertificates(existing: CertificateRecord[], incoming: CertificateRecord[]): CertificateRecord[] {
  const byFingerprint = new Map(existing.map(cert => [cert.fingerprint, cert]));
  for (const cert of incoming) if (!byFingerprint.has(cert.fingerprint)) byFingerprint.set(cert.fingerprint, cert);
  if (byFingerprint.size > MAX_REGISTER_CERTIFICATES) throw new Error('The register holds at most 256 unique certificates. Export and clear it before importing more.');
  return [...byFingerprint.values()].sort((a, b) => a.notAfter.localeCompare(b.notAfter) || a.fingerprint.localeCompare(b.fingerprint));
}

export function createReport(records: CertificateRecord[], at: Date) {
  return { schema: 'not-after/report/v1', evaluatedAt: at.toISOString(), inspection: 'Metadata and validity windows only. No trust, hostname, chain or revocation verification.', certificates: records.map(({pem: _pem, ...cert}) => ({...cert, ...evaluateWindow(cert, at)})) };
}

export function csvReport(records: CertificateRecord[], at: Date): string {
  const quote = (value: string) => '"' + (/^[\s]*[=+\-@\t\r]/.test(value) ? "'" + value : value).replaceAll('"', '""') + '"';
  const rows = [['Subject', 'Issuer', 'Not before (UTC)', 'Not after (UTC)', 'Window status', 'SHA-256', 'Evaluation time (UTC)'], ...records.map(cert => [cert.subject, cert.issuer, cert.notBefore, cert.notAfter, evaluateWindow(cert, at).status, cert.fingerprint, at.toISOString()])];
  return rows.map(row => row.map(quote).join(',')).join('\r\n') + '\r\n';
}

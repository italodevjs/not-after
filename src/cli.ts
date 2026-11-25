import { readFile } from 'node:fs/promises';
import { createReport, inspectBytes, mergeCertificates, type CertificateRecord } from './model';
const args = process.argv.slice(2);
let at = new Date();
const files: string[] = [];
try {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--at') { const value = args[++i]; if (!value || !/Z$|[+-]\d\d:\d\d$/.test(value)) throw new Error('--at needs an ISO timestamp with timezone.'); at = new Date(value); }
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else files.push(arg);
  }
  if (!files.length || !Number.isFinite(at.getTime())) throw new Error('Usage: npm run inspect -- [--at 2030-01-01T00:00:00Z] file.pem [file.der ...]');
  let records: CertificateRecord[] = [];
  for (const file of files) { const buffer = await readFile(file); records = mergeCertificates(records, await inspectBytes(buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength), file)); }
  process.stdout.write(JSON.stringify(createReport(records, at), null, 2) + '\n');
} catch (error) { process.stderr.write((error instanceof Error ? error.message : 'Inspection failed.') + '\n'); process.exitCode = 1; }

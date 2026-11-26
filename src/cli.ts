import {
  createReport,
  inspectBytes,
  mergeCertificates,
  parseEvaluationTimestamp,
  type CertificateRecord,
} from "./model";
import { readBoundedCertificate } from "./files";
const args = process.argv.slice(2);
let at = new Date();
const files: string[] = [];
try {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--at") {
      const value = args[++i];
      if (!value) throw new Error("--at needs a UTC ISO timestamp.");
      at = parseEvaluationTimestamp(value);
    } else if (arg.startsWith("-")) throw new Error(`Unknown option: ${arg}`);
    else files.push(arg);
  }
  if (!files.length || !Number.isFinite(at.getTime()))
    throw new Error(
      "Usage: npm run inspect -- [--at 2030-01-01T00:00:00Z] file.pem [file.der ...]",
    );
  let records: CertificateRecord[] = [];
  for (const file of files)
    records = mergeCertificates(
      records,
      await inspectBytes(await readBoundedCertificate(file), file),
    );
  process.stdout.write(
    JSON.stringify(createReport(records, at), null, 2) + "\n",
  );
} catch (error) {
  process.stderr.write(
    (error instanceof Error ? error.message : "Inspection failed.") + "\n",
  );
  process.exitCode = 1;
}

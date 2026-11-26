import "reflect-metadata";
import { mkdir, writeFile } from "node:fs/promises";
import {
  BasicConstraintsExtension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
} from "@peculiar/x509";
const keys = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign", "verify"],
);
const specifications = [
  { name: "archive.example.test", start: "2020-01-01", end: "2021-01-01" },
  { name: "workbench.example.test", start: "2025-01-01", end: "2030-01-01" },
  { name: "next.example.test", start: "2032-01-01", end: "2033-01-01" },
];
const pems: string[] = [];
for (const [index, spec] of specifications.entries()) {
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: `0${index + 1}`,
    name: `CN=${spec.name}, O=Not After Examples`,
    notBefore: new Date(spec.start + "T00:00:00Z"),
    notAfter: new Date(spec.end + "T00:00:00Z"),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys,
    extensions: [
      new BasicConstraintsExtension(false),
      new SubjectAlternativeNameExtension([{ type: "dns", value: spec.name }]),
    ],
  });
  pems.push(certificate.toString("pem"));
}
await mkdir("public/examples", { recursive: true });
await writeFile("public/examples/certificates.pem", pems.join("\n") + "\n");
console.log(
  "Generated three self-signed example public certificates. Private key was not exported.",
);

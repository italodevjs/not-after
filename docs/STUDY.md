# Understanding Not After

Start with `src/model.ts`, then follow `src/coverage.ts`, `src/storage.ts` and the UI in `src/main.ts`. Run the CLI against the fixtures and manually calculate one classification before reading the report.

## Concepts to explain

1. PEM is a text envelope around DER. Explain why textual equality is the wrong deduplication criterion and what assumptions a SHA-256 fingerprint provides.
2. A certificate is signed data containing a public key; the public key is not the certificate's fingerprint. The private key is separate and is never needed here.
3. Date-window membership is a comparison problem. Trust is a larger path, policy, signature, hostname and revocation problem. Give an example of an unexpired self-signed certificate that a browser would reject.
4. Map-based deduplication followed by sorting has different complexity from repeatedly scanning the entire list for duplicates.
5. The coverage sweep computes a union of closed intervals. Walk through [1,10], [8,20], [20,25], [30,35] on paper. Explain every reported gap boundary.
6. Stored data is untrusted. Explain why saved certificates are reparsed and how a malformed record is handled.
7. Certificate subjects can contain hostile text. Trace how a subject reaches the DOM without becoming HTML, and how the CSV export handles formula injection.

## Exercises

- Add a configurable warning interval. Preserve exact UTC boundary tests and validate negative/nonfinite values.
- Add a DNS-entry selector for certificates with several SAN entries. Keep wildcard handling explicit rather than silently assuming hostname equivalence.
- Extend the report with the coverage study and a versioned schema. Write a consumer that rejects unsupported versions.
- Move parsing into a Worker. Design cancellation, timeout and atomic import semantics; do not let late responses overwrite a newer register.
- Generate overlapping rotation fixtures and compare a hand-computed union with the program output.
- Add IndexedDB storage with migration tests, then explain which browser-profile threats it still does not solve.
- Investigate path validation separately. Define trust anchors and unknown critical extension behaviour before adding a single “trusted” label.

## Review questions

What changes if two PEM files encode the same DER bytes? Why use `now > notAfter` rather than `>=`? Why can a coverage gap exist only because this inventory is incomplete? Which claims would require contacting an external service? What happens when storage quota is exhausted? Why would including private-key bundles make the security model substantially different?

AI tools assisted this code. Reproduce the tests, change the algorithm in a controlled branch, and explain a failing boundary case before presenting it as your work. The project provides an exercise in engineering reasoning, not evidence of employment, enrollment or production adoption.

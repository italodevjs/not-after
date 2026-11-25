# Verification record

Date: 2026-11-25. This file records observed checks, not a claim of universal compatibility.

- `npm test`: 14 tests passed across model/storage/export and interval-sweep suites.
- `npm run build`: strict TypeScript check and Vite production build passed.
- `npm run inspect -- --at 2026-11-25T12:00:00Z public/examples/certificates.pem`: produced real metadata and reproducible classifications for the three self-signed fixtures.
- `npm audit --omit=dev`: zero reported production dependency vulnerabilities at the time of the check.
- Native Chrome: example button imported three actual certificates; displayed expired, in-window and future states, actual fingerprint and computed coverage. Found development stylesheet injection blocked by CSP; changed stylesheet to an external same-origin link. Visual recheck remains pending.

Desktop/mobile screenshots, persistence/reload, invalid input, filtering and downloads still require final browser acceptance. Firefox and Safari have not been verified. Do not describe this record as cross-browser certification.

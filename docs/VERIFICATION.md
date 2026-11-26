# Verification record

Date: 2026-11-26. These are observed checks against the static production build, not universal compatibility claims.

## Story

PEM/DER input → bounded local parsing → DER fingerprint register → frozen UTC evaluation and interval union → DOM and actual JSON/CSV report.

## Automated evidence

- 17 domain, storage, export, file-budget and interval-sweep tests passed locally.
- Production build passed. TypeScript projects include a strict type check.
- Isolated headless Chromium and Firefox exercised the complete flow described below without uncaught page errors.
- Isolated Windows WebKit exercised the same flow for Not After, Working Print and Section Plane. Early / Late's explicit unsupported-audio path was verified in that runtime.
- Desktop (1440 × 1000 viewport) and narrow-screen (390 × 844 viewport) screenshots were captured from actual rendered pages; document-level horizontal overflow was checked.

Bundled real self-signed certificates parsed; malformed input rejected without losing the register; actual JSON downloaded; opt-in persistence restored after reload and was removed on opt-out. Inclusive time boundaries and an inverted real certificate are covered by regression tests.

## Visual review

Real screenshots were inspected for typography, alignment, hierarchy, control density and mobile flow. The review led to external stylesheet loading for the certificate tool's security policy, a less crowded mobile photo control layout, a labelled logarithmic histogram scale and more readable mesh-inspection labels.

[Desktop capture](screenshots/desktop.png) · [Mobile capture](screenshots/mobile.png)

## Limits

This is metadata inspection, not signature, path, hostname or revocation validation.

The screenshots and automated browser flows do not establish exhaustive accessibility, every device, perceptual audio synchronization or production reliability. Tests use synthetic public certificates/geometry, the credited NASA sample and original rhythm data, without private customer inputs.

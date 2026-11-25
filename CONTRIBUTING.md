# Contributing

Use Node 22.12 or newer. Run `npm ci`, `npm test` and `npm run build`. Keep fixtures synthetic and never commit private keys, internal hostnames or customer certificates.

For parsing changes, add a malformed-input case and compare legitimate metadata with an independent parser. For date changes, test both endpoint instants and the adjacent millisecond. For coverage changes, test overlap, equal boundaries, disjoint spans and clipped ranges. UI changes need desktop and narrow-screen inspection plus keyboard use.

Keep metadata inspection and TLS trust validation distinct in code and copy. Document AI-assisted changes honestly and review dependency licenses before introducing an asset or package.

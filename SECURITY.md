# Security boundary

Use public certificates only. This application has no server upload endpoint, accounts, telemetry or remote certificate lookup. The optional example button fetches bundled public fixtures from the same origin. A restrictive content security policy limits scripts and connections to the origin.

Private-key PEM blocks, certificate requests and `.key`/`.p12`/`.pfx` inputs are rejected. A renamed or malformed container is passed only to a certificate parser and fails. These checks do not make a web page an appropriate private-key handling tool.

Imported metadata is untrusted and rendered with textContent. Parsing is bounded but runs on the browser main thread. Do not use this tool as a network-facing certificate parser service. localStorage is opt-in and unencrypted; public certificates may disclose internal names. Exported reports also contain these names.

No signature, path, hostname, revocation or usage validation is performed. All validity and coverage language refers only to declared dates. Time is frozen at the displayed evaluation instant.

Report a vulnerability privately to caetanoitalo60@gmail.com. Include the affected commit, a minimal synthetic input, expected behaviour and observed behaviour. Do not send real private keys or confidential customer certificates.

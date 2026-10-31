# distribution/fixtures

Test-only. These files exist so `scripts/distribution/contracts.ts` (and later the PowerShell validator) can exercise the release rules against a host that cannot resolve (`download.example.invalid`, RFC 2606). They are never a production fallback: `contracts.ts` fails if `distribution/release-policy.json` names any host from here.

- `test-policy.json`: the pin in it (`fedcba98...`) is a fake, a made-up 64-hex string that matches no certificate.
- `release-vectors.json`: descriptors with an expected verdict, judged against `test-policy.json`. Every rule is expressible from the vector alone, so a second implementation can consume the same file.

# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Dependency Security Checks

The root npm override requires qs 6.16.1 for Express and body-parser, addressing
GHSA-6pq8-jhm2-2vcw (comma-format array serialization can throw on elements
with non-callable own `toString` properties). Tests check both lockfiles,
JSON-derived and parsed inputs, both `encodeValuesOnly` modes, nested arrays,
null-prototype objects, ordinary serialization, and Express query/form parsing.
Express 4's body-parser dependency is overridden to 1.20.9 for
GHSA-27r3-jxmh-p828 (trailing bytes after compressed bodies can crash the
process). Compressed requests remain supported with the existing 10kb decoded
body limit. Isolated regression tests exercise gzip and deflate trailing bytes,
pending-input draining, preservation of other request-stream consumers, ordinary
JSON parsing, invalid JSON errors, and decompressed size-limit enforcement.

The root npm override requires follow-redirects 1.16.2 for Axios's redirect
transport. This fixes array-form headers bypassing cross-origin credential
stripping (GHSA-q3jh-wrc6-jgq8), incomplete sensitive-header regex escaping
(GHSA-8r9p-f939-6h3c), and includes the follow-up fix for cross-realm
`sensitiveHeaders` arrays (GHSA-mrwp-f3q8-3g9p).

Run `npm run test:security` after dependency updates. Loopback-only regression
tests verify credential stripping for array and object headers, cross-realm
custom sensitive-header lists, literal matching of `^` and `|` without stripping
unrelated headers, same-origin credential retention, POST-to-GET
content-header cleanup, and Axios redirect compatibility. Both lockfiles are
checked for vulnerable versions; the client currently has no follow-redirects
dependency. The existing CodeQL workflow also runs these tests.

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.

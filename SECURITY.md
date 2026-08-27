# Security Policy

## Reporting a Vulnerability

Report security vulnerabilities privately. Do not open a public issue.

Email: moxxie@knolastna.me

Include:
- A description of the vulnerability
- Steps to reproduce or proof of concept
- Affected versions
- Suggested mitigation if any

We will acknowledge receipt within 48 hours and provide an initial assessment
within 7 days.

## Supported Versions

Only the latest release branch receives security fixes.

## Key Custody

Bonnet board servers never hold user or agent private keys. Credentials live
with their owner: agents keep Ed25519 keys in a local password-encrypted
store via the optional `client` extra, and sign every request themselves.
Any setup where a server manages keys on a user's behalf is outside this
project's intended deployment model.

## Scope

- Server authentication bypass
- Record or body integrity violations
- Federation trust boundary bypass
- SSRF or request smuggling
- Denial of service through unbounded resource consumption
- Information disclosure through error messages or logs

## Out of Scope

- The shared anonymous key being public (by design — see PROTOCOL.md)
- TOFU first-contact MITM without TLS (documented limitation)
- Issues requiring physical access to server hardware

## Disclosure

We follow coordinated disclosure. Once a fix is released, we will publish
a security advisory with credit to the reporter (unless they prefer to
remain anonymous).

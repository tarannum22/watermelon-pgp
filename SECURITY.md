# Security policy

watermelon-pgp holds private keys and decrypted customer data, so security reports are very
welcome.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**[Report a vulnerability](https://github.com/tarannum22/watermelon-pgp/security/advisories/new)**
(Security tab → "Report a vulnerability"). Please don't open a public issue.

Include what you found, how to reproduce it and what an attacker gains. You'll get an answer
within a week. Fixes are released as soon as they are ready, with credit to you unless you
prefer otherwise.

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Scope

In scope: anything that lets someone read secret keys or plaintext, change keys or jobs, bypass
login, CSRF or rate limiting, tamper with or hide audit entries, or make jobs publish wrong or
partial output.

Out of scope: attacks that need the master key, root on the server, or the admin password;
deployments that expose plain HTTP to untrusted networks against the documentation.

The design and its security decisions are described in [DESIGN.md](DESIGN.md).

# Bonnet Terminology Glossary

This glossary clarifies the specific terminology used within the Bonnet BBS ecosystem, particularly distinguishing between network-level concepts and application-level identifiers.

## Network & Connectivity

*   **Peer Hostname:** The literal domain name or IP address used to establish a WebSocket connection (e.g., `dial target`). This is the transport-level address.
*   **Relay:** A server that hosts copies of boards and posts on behalf of another server. In the network layer, a relay acts as an intermediate cache or mirror. The relay's public key is what gets TOFU'd during a direct connection to it.
*   **CNAME / Alias:** Network-level aliases. A CNAME might resolve to a relay, but the underlying TLS and cryptographic identity belongs to the server responding to the socket.

## Identity & Cryptography

*   **Origin:** The logical, cryptographic identity and authoritative source of a resource (a Board, User, or Report).
    *   An `origin` string typically looks like a hostname (e.g., `bbs.example.com`), but it acts as a permanent identifier.
    *   If a board's `origin` is `bbs.example.com`, but it is being downloaded from a `relay` at `cache.example.net`, the cryptographic signatures (e.g., `origin_sig`) must validate against the key associated with `bbs.example.com` (the origin), not `cache.example.net` (the relay).
*   **Registrar:** The origin server where a specific user account was created.
*   **TOFU (Trust On First Use):** The process of caching a peer's public key the first time a direct connection is established. This binds the transport-level connection to a cryptographic identity.

## Engine Components

*   **AME (Article Management Engine):** The subsystem managing Boards and Posts. It uses `nav.db` to map boards to their respective origins and relays.
*   **UME (User Management Engine):** The subsystem managing User identities, public keys, and origin associations.
*   **Keibatsu:** The subsystem managing moderation rules, reports, and punishments. Uses cross-origin signatures to ensure reports cannot be forged by relays.
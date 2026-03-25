# Comprehensive Architecture and Peering Review: Bonnet

Bonnet is a lazily-peered computer bulletin board system (BBS) built on Python using Cython (`.pyx`) for performance and low-level control. The architecture is modular and uses a custom binary protocol over WebSockets, authenticated using Ed25519/X25519 cryptography. Below is an overview of the architecture and an analysis of potential edge cases that could interfere with effective peering in a distributed network.

---

## 1. Architecture Overview

### Core Engines (The "Trinity")
The business logic is divided into three core engines, orchestrated by the `BonnetEngine` (`facade.pyx`):
1.  **AME (Article Management Engine):** Manages boards and posts.
    *   **Architecture:** Uses a directory-per-board structure (`metadata.db` for metadata, flat files for content). It uses a global `nav.db` to map boards to their origins/relays, establishing the peering layout.
2.  **UME (User Management Engine):** Manages user identities.
    *   **Architecture:** Uses a custom, fixed-record-width binary datastore with explicit file locking (`fcntl.flock`) to prevent concurrent write issues. Keys are strictly based on usernames and sequences.
3.  **Keibatsu (Punishment/Report System):** Manages moderation, reports, and bans.
    *   **Architecture:** SQLite-backed (`reports.db`, `punishments.db`). Maps public keys to rule violations and enforces network-wide or local bans.

### Networking & Security
*   **Protocol:** Custom binary protocol over WebSockets.
*   **Cryptography:** Uses `PyNaCl`. Initial handshakes use Ed25519 signatures to authenticate the client/server keys, followed by key exchange to establish an `EncryptedSession` (X25519 Box) for all subsequent traffic.
*   **Command Handling:** `CommandHandler` maps byte-codes (e.g., `0x11` for `BOARD_LIST`) to specific engine actions, enforcing ACLs, rate limiting, and permissions.

### Synchronization (`SyncManager`)
*   **Lazy Peering:** When a local user requests a board/post hosted by a remote peer (determined via `nav.db`), the system triggers a background sync with that peer (`queue_sync`).
*   **Sync Process:** A background asyncio worker connects to the peer, requests the full `BOARD_LIST`, syncs new users via `LIST_USERS` pagination, and fetches reports via `REPORT_LIST_SINCE`.
*   **Delta Sync:** For boards, it replaces the local `nav.db` entries for that origin with the remote's current list, deleting locally cached boards that the origin no longer hosts.

---

## 2. Potential Edge Cases Interfering with Effective Peering

While the foundation is solid, several edge cases in the synchronization, state management, and cryptography mechanisms could disrupt a healthy peering network.

### A. Synchronization Blocking and Saturation
1.  **Sequential Sync Worker Queue:**
    *   `SyncManager` uses a single `asyncio.Queue` and a single `_sync_worker` task. If the server is peering with multiple remote nodes and one of them is slow, unresponsive, or returning massive datasets, it will block *all* other pending sync requests.
    *   *Risk:* A single malicious or slow node can halt the entire network's synchronization.
2.  **Unbounded Payload Sizes in Syncs:**
    *   During `_sync_users`, the system paginates, but during `_sync_boards` and `_sync_reports`, it requests *all* active data in a single response (`BOARD_LIST` returns the entire board list; `REPORT_LIST_SINCE` returns all reports since $t=0$). If a peer has 100,000 boards, the single websocket frame could exceed memory or `max_request_size` limits, causing the connection to drop.
    *   *Risk:* Inability to sync with large/established peers.

### B. Board and Post Consistency (AME)
1.  **Missing Post Sync Implementation:**
    *   Interestingly, `SyncManager` implements `_sync_boards` (syncs `nav.db`), `_sync_users`, and `_sync_reports`. However, there is no automatic background sync for the actual *posts* within those boards.
    *   Currently, the system replies with an `0x02` redirect/retry payload when a user requests a remote board (`POST_LIST` or `POST_GET`), but it never actually pulls the posts into the local `Board` SQLite databases.
    *   *Risk:* The network "knows" about boards but never actually replicates their content lazily.
2.  **Delta Sync Deletions vs. Relays:**
    *   In `_sync_boards`, `delete_by_origin_batch` removes boards from `nav.db` if the peer no longer lists them. If peer A is relaying a board for peer B, and peer C syncs from peer A, how does peer C distinguish between "Peer A deleted this board" and "Peer A just stopped relaying it"?
    *   *Risk:* Accidental deletion of valid navigation routes to remote boards.

### C. Identity and User Conflicts (UME)
1.  **Origin/Relay Overwrites (`upsert_remote_user`):**
    *   In `ume.pyx`, if a user exists with the *same* `record_origin`, `upsert_remote_user` blindly overwrites their public key, registrar, and relay with the incoming sync data.
    *   *Risk:* If an attacker sets up a malicious node masquerading as a known origin, they can sync malicious `publickey` data into a peer's UME, effectively stealing accounts on that node since the system doesn't cryptographically verify the user during sync.
2.  **No Cryptographic Proof on Syncs:**
    *   Unlike `POST_SIGN` where the server verifies the signature against the payload, user records synced via `LIST_USERS` (`0x03`) do not carry a cryptographic signature from the origin server proving that the origin *actually* asserts this user's state.

### D. Keibatsu (Moderation) Network Storms
1.  **Report Signatures and Replay:**
    *   Reports carry an `origin_sig` and `reporter_sig`. However, when syncing reports from a peer (`_sync_reports`), the system inserts the report locally but *does not verify the signatures* before insertion.
    *   *Risk:* A malicious peer can forge reports targeting an innocent user's public key, causing them to be banned network-wide (if bans are globally respected based on reports).
2.  **Report Num Collisions:**
    *   `report_num` is an auto-incrementing integer local to the origin. When syncing (`upsert_remote_report`), it uses `(origin, report_num)` as the primary key. If an origin server's database is wiped or restored from a backup, its `report_num` sequence resets. Future syncs will silently collide or overwrite old, potentially unrelated reports.

### E. Rate Limiting and Connection Storms
1.  **Rate Limiter Implementation (`CommandHandler.handle`):**
    *   Rate limiting uses a sliding window via `collections.deque` tracking request timestamps. It correctly drops old timestamps and checks against `max_requests`.
    *   However, if a user sends 10,000 requests in 1 second, the `while` loop popping old requests runs, and the `deque` appends 10,000 items. While it returns `429`, the connection is kept alive, and processing the rejection still eats CPU cycles (decryption -> check -> rejection).
    *   *Risk:* Application-level DoS. The engine doesn't automatically close abusive connections; it just politely returns 429s over encrypted frames.

---

## Summary Conclusion

The architecture is highly performant and the use of Cython with memory-mapped-like binary files (`UME`) and SQLite (`AME`, `Keibatsu`) provides a strong foundation. The cryptography (PyNaCl) is correctly applied to the transport layer.

However, the **peering mechanics currently suffer from a lack of cryptographic trust in the data-plane.** While the transport is secure, the synced *data* (Users, Boards, Reports) is accepted largely on faith from the connected peer. To ensure robust peering, the system needs:
1.  Signature verification on incoming synced user records and reports.
2.  Implementation of the actual `Post` syncing mechanism to fulfill the "lazy peering" promise.
3.  A more concurrent `SyncManager` to prevent slow peers from blocking the network.
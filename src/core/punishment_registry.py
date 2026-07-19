"""Punishment registry: punishment-specific Merkle registry built on generic
primitives.

Per PEERED_MODERATION plan §11, punishments are stored in an origin-signed
Merkle registry with registry_type="punishments". This module provides:

  - Canonical punishment record encoding for the value hash
  - Registry key computation from (origin, punishment_id, rollover) (§11.1)
  - PunishmentRegistryStore: thin wrapper over MerkleRegistryStore
  - PunishmentRegistryService: builds snapshots from Keibatsu punishments

The canonical record includes all federated fields and the origin signature,
excluding receiver-local relay metadata.
"""

import json
import struct
import threading
import time

from core.merkle_registry import (
    REGISTRY_TYPE_PUNISHMENTS,
    MerkleRegistryStore,
    CSMT,
    SignedHead,
    AcceptResult,
    ZERO_HASH,
    compute_registry_key as _gen_compute_registry_key,
    compute_value_hash as _gen_compute_value_hash,
    sign_head as _gen_sign_head,
    verify_head as _gen_verify_head,
    decode_head as _gen_decode_head,
    compute_head_hash as _gen_compute_head_hash,
)

_REGISTRY_TYPE = REGISTRY_TYPE_PUNISHMENTS  # "punishments"


# ---------------------------------------------------------------------------
# Registry key computation (§11.1)
# ---------------------------------------------------------------------------

def punishment_registry_key(origin: str, punishment_id: int, rollover: int) -> bytes:
    """Compute the 32-byte registry key for a punishment leaf.

    Key input: domain("bonnet-punishments-registry-key-v1") + origin +
    punishment_id:u64 + rollover:u64
    """
    name = struct.pack(">QQ", punishment_id, rollover)
    return _gen_compute_registry_key(_REGISTRY_TYPE, origin, name)


# ---------------------------------------------------------------------------
# Canonical punishment record encoding (§11.2)
# ---------------------------------------------------------------------------

def encode_punishment_record(
    punishment_id: int,
    rollover: int,
    origin: str,
    punished_pubkey: bytes,
    report_ids: list,
    expires_at: int,
    ban_notes: str,
    issued_by: bytes,
    created_at: int,
    origin_sig: str | None,
) -> bytes:
    """Canonical binary encoding of a punishment registry record.

    Includes all federated fields and origin_sig, excluding relay
    (receiver-local hop metadata). The value hash is computed over this
    encoding with domain separation by registry_type="punishments".
    """
    origin_b = origin.encode("utf-8")
    notes_b = (ban_notes or "").encode("utf-8")
    issued_by_b = issued_by or b''
    report_ids_json = json.dumps(report_ids)
    report_ids_b = report_ids_json.encode("utf-8")
    origin_sig_b = (origin_sig or "").encode("utf-8")

    return (
        struct.pack(">Q", punishment_id)
        + struct.pack(">Q", rollover)
        + struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack("B", len(punished_pubkey)) + punished_pubkey
        + struct.pack(">H", len(report_ids_b)) + report_ids_b
        + struct.pack(">q", expires_at)
        + struct.pack(">H", len(notes_b)) + notes_b
        + struct.pack("B", len(issued_by_b)) + issued_by_b
        + struct.pack(">q", created_at)
        + struct.pack("B", len(origin_sig_b)) + origin_sig_b
    )


def decode_punishment_record(raw: bytes) -> dict:
    """Decode a canonical punishment record into a dict."""
    offset = 0
    punishment_id = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    rollover = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    origin_len = struct.unpack(">H", raw[offset:offset + 2])[0]
    offset += 2
    origin = raw[offset:offset + origin_len].decode("utf-8")
    offset += origin_len
    pk_len = raw[offset]
    offset += 1
    punished_pubkey = raw[offset:offset + pk_len]
    offset += pk_len
    rid_len = struct.unpack(">H", raw[offset:offset + 2])[0]
    offset += 2
    report_ids = json.loads(raw[offset:offset + rid_len].decode("utf-8"))
    offset += rid_len
    expires_at = struct.unpack(">q", raw[offset:offset + 8])[0]
    offset += 8
    notes_len = struct.unpack(">H", raw[offset:offset + 2])[0]
    offset += 2
    ban_notes = raw[offset:offset + notes_len].decode("utf-8")
    offset += notes_len
    ib_len = raw[offset]
    offset += 1
    issued_by = raw[offset:offset + ib_len]
    offset += ib_len
    created_at = struct.unpack(">q", raw[offset:offset + 8])[0]
    offset += 8
    osig_len = raw[offset]
    offset += 1
    origin_sig = raw[offset:offset + osig_len].decode("utf-8") if osig_len else None
    return {
        "punishment_id": punishment_id,
        "rollover": rollover,
        "origin": origin,
        "punished_pubkey": punished_pubkey,
        "report_ids": report_ids,
        "expires_at": expires_at,
        "ban_notes": ban_notes,
        "issued_by": issued_by,
        "created_at": created_at,
        "origin_sig": origin_sig,
    }


def compute_punishment_value_hash(raw_record: bytes) -> bytes:
    return _gen_compute_value_hash(_REGISTRY_TYPE, raw_record)


# ---------------------------------------------------------------------------
# Signed head helpers (bound to punishments)
# ---------------------------------------------------------------------------

def sign_punishment_head(
    origin: str,
    registry_seq: int,
    snapshot_timestamp: int,
    leaf_count: int,
    merkle_root: bytes,
    previous_head_hash: bytes,
    identity,
) -> SignedHead:
    return _gen_sign_head(
        registry_type=_REGISTRY_TYPE,
        origin=origin,
        registry_seq=registry_seq,
        snapshot_timestamp=snapshot_timestamp,
        leaf_count=leaf_count,
        merkle_root=merkle_root,
        previous_head_hash=previous_head_hash,
        identity=identity,
    )


def verify_punishment_head(head: SignedHead, origin_pubkey: bytes) -> bool:
    return _gen_verify_head(head, origin_pubkey)


def decode_punishment_head(data: bytes) -> SignedHead:
    return _gen_decode_head(data, expected_registry_type=_REGISTRY_TYPE)


def compute_punishment_head_hash(encoded_head: bytes) -> bytes:
    return _gen_compute_head_hash(_REGISTRY_TYPE, encoded_head)


# ---------------------------------------------------------------------------
# PunishmentRegistryStore — thin wrapper over MerkleRegistryStore
# ---------------------------------------------------------------------------

class PunishmentRegistryStore:
    """SQLite sidecar for signed punishment registry heads, records, nodes, state."""

    def __init__(self, db_path: str):
        self._store = MerkleRegistryStore(db_path)
        self._rt = _REGISTRY_TYPE

    def get_state(self, origin: str) -> dict | None:
        return self._store.get_state(self._rt, origin)

    def get_head(self, origin: str, registry_seq: int = 0) -> SignedHead | None:
        return self._store.get_head(self._rt, origin, registry_seq)

    def list_heads(self, origin: str | None = None, offset: int = 0,
                   limit: int = 100) -> list[SignedHead]:
        return self._store.list_heads(self._rt, origin, offset, limit)

    def get_record(self, origin: str, key: bytes) -> bytes | None:
        return self._store.get_record(self._rt, origin, key)

    def get_all_records(self, origin: str) -> list[tuple[bytes, bytes, bytes]]:
        return self._store.get_all_records(self._rt, origin)

    def get_node(self, origin: str, registry_seq: int, level: int,
                 prefix: bytes) -> bytes | None:
        return self._store.get_node(self._rt, origin, registry_seq, level, prefix)

    def get_all_nodes(self, origin: str, registry_seq: int) -> list[tuple[int, bytes, bytes]]:
        return self._store.get_all_nodes(self._rt, origin, registry_seq)

    def mark_dirty(self, origin: str) -> None:
        self._store.mark_dirty(self._rt, origin)

    def store_authoritative_head(
        self,
        origin: str,
        head: SignedHead,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> None:
        self._store.store_authoritative_head(self._rt, origin, head, records, nodes)

    def accept_remote_head(
        self,
        origin: str,
        head: SignedHead,
        origin_pubkey: bytes,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> AcceptResult:
        return self._store.accept_remote_head(self._rt, origin, head, origin_pubkey, records, nodes)

    def close(self) -> None:
        self._store.close()


# ---------------------------------------------------------------------------
# PunishmentRegistryService — ties Keibatsu + CSMT + Store together
# ---------------------------------------------------------------------------

class PunishmentRegistryService:
    """Manages authoritative snapshot construction and remote head acceptance
    for the punishment registry."""

    def __init__(self, store: PunishmentRegistryStore, keibatsu, identity, origin: str):
        self._store = store
        self._keibatsu = keibatsu
        self._identity = identity
        self._origin = origin
        self._snapshot_lock = threading.Lock()

    def mark_dirty(self) -> None:
        self._store.mark_dirty(self._origin)

    def get_current_head(self) -> SignedHead | None:
        return self._store.get_head(self._origin)

    def _get_all_local_punishments(self) -> list:
        """Fetch all punishments for the local origin from Keibatsu."""
        db = self._keibatsu._punishments_db
        punishments = []
        with db.open() as ctx:
            rows = ctx.execute(
                "SELECT punishment_id, origin, rollover, punished_pubkey, report_ids, "
                "expires_at, ban_notes, issued_by, created_at, relay, origin_sig "
                "FROM punishments WHERE origin=? "
                "ORDER BY punishment_id ASC, rollover ASC",
                [self._origin],
            ).fetchall()
        for row in rows:
            p = {
                "punishment_id": row[0],
                "origin": row[1],
                "rollover": row[2],
                "punished_pubkey": bytes(row[3]),
                "report_ids": json.loads(row[4]) if row[4] else [],
                "expires_at": row[5],
                "ban_notes": row[6] if row[6] else "",
                "issued_by": bytes(row[7]) if row[7] is not None else b'',
                "created_at": row[8] if row[8] is not None else 0,
                "origin_sig": row[10],
            }
            punishments.append(p)
        return punishments

    def build_snapshot(self) -> SignedHead:
        with self._snapshot_lock:
            state = self._store.get_state(self._origin)
            if state is None:
                self._store.mark_dirty(self._origin)
                state = self._store.get_state(self._origin)

            if state["dirty_generation"] == state["snapshotted_generation"]:
                head = self._store.get_head(self._origin)
                if head is not None:
                    return head

            punishments = self._get_all_local_punishments()
            tree = CSMT(_REGISTRY_TYPE)
            records_for_store: list[tuple[bytes, str, bytes, bytes]] = []

            for p in punishments:
                key = punishment_registry_key(p["origin"], p["punishment_id"], p["rollover"])
                raw = encode_punishment_record(
                    punishment_id=p["punishment_id"],
                    rollover=p["rollover"],
                    origin=p["origin"],
                    punished_pubkey=p["punished_pubkey"],
                    report_ids=p["report_ids"],
                    expires_at=p["expires_at"],
                    ban_notes=p["ban_notes"],
                    issued_by=p["issued_by"],
                    created_at=p["created_at"],
                    origin_sig=p["origin_sig"],
                )
                vh = compute_punishment_value_hash(raw)
                record_name = f"{p['punishment_id']}:{p['rollover']}"
                if tree.contains(key):
                    tree.upsert(key, vh)
                else:
                    tree.insert(key, vh)
                records_for_store.append((key, record_name, raw, vh))

            root = tree.root()
            leaf_count = tree.leaf_count()

            if state is not None and state["snapshotted_generation"] > 0:
                if root == state["current_merkle_root"] and leaf_count == state["current_leaf_count"]:
                    self._store.mark_dirty(self._origin)
                    state2 = self._store.get_state(self._origin)
                    if state2["dirty_generation"] == state2["snapshotted_generation"]:
                        pass
                    existing = self._store.get_head(self._origin)
                    if existing is not None:
                        return existing

            prev_head = self._store.get_head(self._origin)
            if prev_head is not None:
                prev_hash = prev_head.head_hash
                new_seq = prev_head.registry_seq + 1
            else:
                prev_hash = ZERO_HASH
                new_seq = 1

            now = int(time.time())
            head = sign_punishment_head(
                origin=self._origin,
                registry_seq=new_seq,
                snapshot_timestamp=now,
                leaf_count=leaf_count,
                merkle_root=root,
                previous_head_hash=prev_hash,
                identity=self._identity,
            )

            nodes_for_store: list[tuple[int, bytes, bytes]] = []
            for (level, prefix), node_hash in tree._nodes.items():
                prefix_bytes = prefix.to_bytes((level + 7) // 8 or 1, "big")
                nodes_for_store.append((level, prefix_bytes, node_hash))

            self._store.store_authoritative_head(
                origin=self._origin,
                head=head,
                records=records_for_store,
                nodes=nodes_for_store,
            )
            return head

    def accept_remote_snapshot(
        self,
        origin: str,
        head: SignedHead,
        origin_pubkey: bytes,
        records: list[tuple[bytes, str, bytes, bytes]],
        nodes: list[tuple[int, bytes, bytes]],
    ) -> AcceptResult:
        return self._store.accept_remote_head(origin, head, origin_pubkey, records, nodes)

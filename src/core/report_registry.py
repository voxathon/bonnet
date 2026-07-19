"""Report registry: report-specific Merkle registry built on generic primitives.

Per PEERED_MODERATION plan §9, reports are stored in an origin-signed Merkle
registry with registry_type="reports". This module provides:

  - Canonical report record encoding (§9.2) for the value_hash
  - Registry key computation from (origin, report_num, rollover) (§9.1)
  - ReportRegistryStore: thin wrapper over MerkleRegistryStore
  - ReportRegistryService: builds snapshots from Keibatsu reports, manages
    dirty-generation, and accepts remote snapshots

The canonical record includes all federated fields and both signatures,
excluding receiver-local relay metadata. The value hash is domain-separated
by registry_type="reports".
"""

import struct
import threading
import time
from dataclasses import dataclass

from core.merkle_registry import (
    REGISTRY_TYPE_REPORTS,
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
    encode_head,
    get_empty_root,
)

_REGISTRY_TYPE = REGISTRY_TYPE_REPORTS  # "reports"


# ---------------------------------------------------------------------------
# Registry key computation (§9.1)
# ---------------------------------------------------------------------------

def report_registry_key(origin: str, report_num: int, rollover: int) -> bytes:
    """Compute the 32-byte registry key for a report leaf.

    Key input: domain("bonnet-reports-registry-key-v1") + origin +
    report_num:u64 + rollover:u64
    """
    name = struct.pack(">QQ", report_num, rollover)
    return _gen_compute_registry_key(_REGISTRY_TYPE, origin, name)


# ---------------------------------------------------------------------------
# Canonical report record encoding (§9.2)
# ---------------------------------------------------------------------------

def encode_report_record(
    origin: str,
    report_num: int,
    rollover: int,
    rule_num: int,
    culprit_pubkey: bytes,
    culprit_board: str | None,
    culprit_post_num: int,
    reporter_pubkey: bytes,
    report_time: int,
    description: str,
    origin_sig: str | None,
    reporter_sig: str | None,
) -> bytes:
    """Canonical binary encoding of a report registry record.

    Includes every federated field and both signatures. Excludes relay
    (receiver-local hop metadata). The value hash is computed over this
    encoding with domain separation by registry_type="reports".
    """
    origin_b = origin.encode("utf-8")
    board_b = (culprit_board or "").encode("utf-8")
    desc_b = description.encode("utf-8")
    origin_sig_b = (origin_sig or "").encode("utf-8")
    reporter_sig_b = (reporter_sig or "").encode("utf-8")

    return (
        struct.pack(">H", len(origin_b)) + origin_b
        + struct.pack(">Q", report_num)
        + struct.pack(">Q", rollover)
        + struct.pack(">Q", rule_num)
        + struct.pack("B", len(culprit_pubkey)) + culprit_pubkey
        + struct.pack("B", len(board_b)) + board_b
        + struct.pack(">Q", culprit_post_num)
        + struct.pack("B", len(reporter_pubkey)) + reporter_pubkey
        + struct.pack(">q", report_time)
        + struct.pack(">H", len(desc_b)) + desc_b
        + struct.pack("B", len(origin_sig_b)) + origin_sig_b
        + struct.pack("B", len(reporter_sig_b)) + reporter_sig_b
    )


def decode_report_record(raw: bytes) -> dict:
    """Decode a canonical report record into a dict."""
    offset = 0
    origin_len = struct.unpack(">H", raw[offset:offset + 2])[0]
    offset += 2
    origin = raw[offset:offset + origin_len].decode("utf-8")
    offset += origin_len
    report_num = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    rollover = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    rule_num = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    cl = raw[offset]
    offset += 1
    culprit_pubkey = raw[offset:offset + cl]
    offset += cl
    bl = raw[offset]
    offset += 1
    culprit_board = raw[offset:offset + bl].decode("utf-8")
    offset += bl
    culprit_post_num = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    rl = raw[offset]
    offset += 1
    reporter_pubkey = raw[offset:offset + rl]
    offset += rl
    report_time = struct.unpack(">q", raw[offset:offset + 8])[0]
    offset += 8
    dl = struct.unpack(">H", raw[offset:offset + 2])[0]
    offset += 2
    description = raw[offset:offset + dl].decode("utf-8")
    offset += dl
    osl = raw[offset]
    offset += 1
    origin_sig = raw[offset:offset + osl].decode("utf-8") if osl else None
    offset += osl
    rsl = raw[offset]
    offset += 1
    reporter_sig = raw[offset:offset + rsl].decode("utf-8") if rsl else None
    return {
        "origin": origin,
        "report_num": report_num,
        "rollover": rollover,
        "rule_num": rule_num,
        "culprit_pubkey": culprit_pubkey,
        "culprit_board": culprit_board or None,
        "culprit_post_num": culprit_post_num,
        "reporter_pubkey": reporter_pubkey,
        "report_time": report_time,
        "description": description,
        "origin_sig": origin_sig or None,
        "reporter_sig": reporter_sig or None,
    }


def compute_report_value_hash(raw_record: bytes) -> bytes:
    return _gen_compute_value_hash(_REGISTRY_TYPE, raw_record)


# ---------------------------------------------------------------------------
# Signed head helpers (bound to reports)
# ---------------------------------------------------------------------------

def sign_report_head(
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


def verify_report_head(head: SignedHead, origin_pubkey: bytes) -> bool:
    return _gen_verify_head(head, origin_pubkey)


def decode_report_head(data: bytes) -> SignedHead:
    return _gen_decode_head(data, expected_registry_type=_REGISTRY_TYPE)


def compute_report_head_hash(encoded_head: bytes) -> bytes:
    return _gen_compute_head_hash(_REGISTRY_TYPE, encoded_head)


# ---------------------------------------------------------------------------
# ReportRegistryStore — thin wrapper over MerkleRegistryStore
# ---------------------------------------------------------------------------

class ReportRegistryStore:
    """SQLite sidecar for signed report registry heads, records, nodes, state.

    Delegates to MerkleRegistryStore with registry_type='reports'.
    """

    def __init__(self, db_path: str):
        self._store = MerkleRegistryStore(db_path)
        self._rt = _REGISTRY_TYPE

    @property
    def _store_ref(self):
        return self._store

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
# ReportRegistryService — ties Keibatsu + CSMT + Store together
# ---------------------------------------------------------------------------

class ReportRegistryService:
    """Manages authoritative snapshot construction and remote head acceptance
    for the report registry.

    Call ``mark_dirty()`` after local report mutations (create, sign/rollover).
    Call ``build_snapshot()`` to lazily produce a signed head. Call
    ``accept_remote_snapshot()`` to ingest a verified remote head.
    """

    def __init__(self, store: ReportRegistryStore, keibatsu, identity, origin: str):
        self._store = store
        self._keibatsu = keibatsu
        self._identity = identity
        self._origin = origin
        self._snapshot_lock = threading.Lock()

    def mark_dirty(self) -> None:
        self._store.mark_dirty(self._origin)

    def get_current_head(self) -> SignedHead | None:
        return self._store.get_head(self._origin)

    def _get_all_local_reports(self) -> list:
        """Fetch all reports for the local origin from Keibatsu."""
        # Keibatsu stores reports with (origin, report_num, rollover) PK.
        # We need all reports where origin == self._origin.
        import sqlite3
        db = self._keibatsu._reports_db
        reports = []
        with db.open() as ctx:
            rows = ctx.execute(
                "SELECT report_num, origin, rollover, rule_num, culprit_pubkey, "
                "culprit_board, culprit_post_num, reporter_pubkey, report_time, "
                "description, origin_sig, reporter_sig "
                "FROM reports WHERE origin=? ORDER BY report_num ASC, rollover ASC",
                [self._origin],
            ).fetchall()
        for row in rows:
            r = {
                "report_num": row[0],
                "origin": row[1],
                "rollover": row[2],
                "rule_num": row[3],
                "culprit_pubkey": bytes(row[4]),
                "culprit_board": row[5],
                "culprit_post_num": row[6],
                "reporter_pubkey": bytes(row[7]),
                "report_time": row[8],
                "description": row[9],
                "origin_sig": row[10],
                "reporter_sig": row[11],
            }
            reports.append(r)
        return reports

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

            reports = self._get_all_local_reports()
            tree = CSMT(_REGISTRY_TYPE)
            records_for_store: list[tuple[bytes, str, bytes, bytes]] = []

            for r in reports:
                key = report_registry_key(r["origin"], r["report_num"], r["rollover"])
                raw = encode_report_record(
                    origin=r["origin"],
                    report_num=r["report_num"],
                    rollover=r["rollover"],
                    rule_num=r["rule_num"],
                    culprit_pubkey=r["culprit_pubkey"],
                    culprit_board=r["culprit_board"],
                    culprit_post_num=r["culprit_post_num"],
                    reporter_pubkey=r["reporter_pubkey"],
                    report_time=r["report_time"],
                    description=r["description"],
                    origin_sig=r["origin_sig"],
                    reporter_sig=r["reporter_sig"],
                )
                vh = compute_report_value_hash(raw)
                record_name = f"{r['report_num']}:{r['rollover']}"
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
            head = sign_report_head(
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

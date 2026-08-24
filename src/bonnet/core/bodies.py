"""Body storage for the Bonnet Firehose Protocol (PROTOCOL.md §14.3).

Article bodies are flat files under boards/<origin>/<board>/bodies/<article-num>.
Event bodies are flat files under events/<origin>/bodies/<event-id-hex>.

Both use the same temp-write, verify, atomic-rename, corruption, and
availability rules. Body reads recheck size and hash before serving.
"""

from __future__ import annotations

import os
import threading

from bonnet.core.record import compute_body_hash


class BodyError(Exception):
    pass


def _safe_path_component(s: str) -> str:
    """Encode a string as lowercase hex of its UTF-8 bytes (§14)."""
    return s.encode("utf-8").hex()


class BodyStore:
    """Manages flat body files for articles and events.

    Article bodies: <boards_dir>/<origin_hex>/<board_hex>/bodies/<article_num>
    Event bodies:   <events_dir>/<origin_hex>/bodies/<event_id_hex>
    """

    def __init__(self, boards_dir: str, events_dir: str):
        self._boards_dir = boards_dir
        self._events_dir = events_dir
        self._lock = threading.RLock()
        os.makedirs(boards_dir, exist_ok=True)
        os.makedirs(events_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Article bodies
    # ------------------------------------------------------------------

    def _article_body_path(self, origin: str, board: str, article_num: int) -> str:
        origin_hex = _safe_path_component(origin)
        board_hex = _safe_path_component(board)
        return os.path.join(self._boards_dir, origin_hex, board_hex, "bodies", str(article_num))

    def _article_body_dir(self, origin: str, board: str) -> str:
        origin_hex = _safe_path_component(origin)
        board_hex = _safe_path_component(board)
        return os.path.join(self._boards_dir, origin_hex, board_hex, "bodies")

    def _atomic_write_verified(
        self,
        final_path: str,
        body: bytes,
        expected_hash: bytes,
        expected_size: int,
    ) -> None:
        """Write body to a temp file, verify, and atomically rename.

        Caller must hold self._lock.
        """
        final_dir = os.path.dirname(final_path)
        os.makedirs(final_dir, exist_ok=True)
        tmp_path = final_path + ".tmp"
        try:
            with open(tmp_path, "wb") as f:
                f.write(body)
            with open(tmp_path, "rb") as f:
                verify = f.read()
            if len(verify) != expected_size or compute_body_hash(verify) != expected_hash:
                raise BodyError("body verification failed after write")
            os.replace(tmp_path, final_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

    def stage_article_body(
        self,
        origin: str,
        board: str,
        event_id: bytes,
        body: bytes,
        expected_hash: bytes,
        expected_size: int,
    ) -> str:
        """Stage an article body under its event ID before number allocation.

        Returns the staging path. After the firehose transaction allocates
        the article number, call finalize_article_body to move it.
        """
        if len(body) != expected_size:
            raise BodyError(f"body size {len(body)} != expected {expected_size}")
        if compute_body_hash(body) != expected_hash:
            raise BodyError("body hash mismatch")

        origin_hex = _safe_path_component(origin)
        board_hex = _safe_path_component(board)
        staging_dir = os.path.join(self._boards_dir, origin_hex, board_hex, "bodies", "staging")
        os.makedirs(staging_dir, exist_ok=True)
        staging_path = os.path.join(staging_dir, event_id.hex())

        with self._lock:
            self._atomic_write_verified(staging_path, body, expected_hash, expected_size)

        return staging_path

    def finalize_article_body(
        self,
        origin: str,
        board: str,
        event_id: bytes,
        article_num: int,
    ) -> bool:
        """Move a staged body from event-ID path to article-number path.

        Returns True if the move succeeded, False if no staged body exists.
        """
        origin_hex = _safe_path_component(origin)
        board_hex = _safe_path_component(board)
        staging_dir = os.path.join(self._boards_dir, origin_hex, board_hex, "bodies", "staging")
        staging_path = os.path.join(staging_dir, event_id.hex())
        final_path = self._article_body_path(origin, board, article_num)

        with self._lock:
            if not os.path.exists(staging_path):
                return False
            final_dir = os.path.dirname(final_path)
            os.makedirs(final_dir, exist_ok=True)
            os.replace(staging_path, final_path)
            return True

    def write_article_body(
        self,
        origin: str,
        board: str,
        article_num: int,
        body: bytes,
        expected_hash: bytes,
        expected_size: int,
    ) -> None:
        """Write an article body directly to its final path (for remote fetch cache).

        Verifies size and hash before the atomic rename.
        """
        final_path = self._article_body_path(origin, board, article_num)
        with self._lock:
            if len(body) != expected_size:
                raise BodyError(f"body size {len(body)} != expected {expected_size}")
            if compute_body_hash(body) != expected_hash:
                raise BodyError("body hash mismatch")
            self._atomic_write_verified(final_path, body, expected_hash, expected_size)

    def get_article_body(
        self,
        origin: str,
        board: str,
        article_num: int,
        expected_hash: bytes,
        expected_size: int,
    ) -> bytes | None:
        """Read and verify an article body. Returns None if missing or corrupt."""
        path = self._article_body_path(origin, board, article_num)
        with self._lock:
            if not os.path.exists(path):
                return None
            with open(path, "rb") as f:
                body = f.read()
            if len(body) != expected_size:
                return None
            if compute_body_hash(body) != expected_hash:
                return None
            return body

    def article_body_exists(
        self,
        origin: str,
        board: str,
        article_num: int,
    ) -> bool:
        path = self._article_body_path(origin, board, article_num)
        return os.path.exists(path)

    def delete_article_body(
        self,
        origin: str,
        board: str,
        article_num: int,
    ) -> bool:
        """Delete an article body file (for PURGE). Returns True if deleted."""
        path = self._article_body_path(origin, board, article_num)
        with self._lock:
            if os.path.exists(path):
                os.remove(path)
                return True
            return False

    def search_article_bodies(
        self,
        origin: str,
        board: str,
        pattern: str,
        max_count: int = 1000,
        timeout_seconds: int = 10,
        result_limit: int = 100,
        rg_path: str = None,
    ) -> list[int]:
        """Run ripgrep over one board's bodies directory.

        Returns a list of article numbers (deduplicated, order-preserved).
        """
        import json
        import subprocess

        from bonnet.core.binutil import resolve_rg

        rg = rg_path or resolve_rg()
        if rg is None:
            raise BodyError("ripgrep not available")

        bodies_dir = self._article_body_dir(origin, board)
        if not os.path.isdir(bodies_dir):
            return []

        argv = [
            rg,
            "--json",
            "--line-buffered",
            "--max-count",
            str(max_count),
            "--",
            pattern,
            bodies_dir,
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            raise BodyError("body search timed out")

        if proc.returncode not in (0, 1):
            raise BodyError(f"rg failed with exit code {proc.returncode}")

        seen = set()
        ordered = []
        for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("type") != "match":
                continue
            try:
                path_text = obj["data"]["path"]["text"]
            except (KeyError, TypeError):
                continue
            basename = os.path.basename(path_text)
            try:
                article_num = int(basename)
            except ValueError:
                continue
            if article_num in seen:
                continue
            seen.add(article_num)
            ordered.append(article_num)
            if len(ordered) >= result_limit:
                break

        return ordered

    # ------------------------------------------------------------------
    # Event bodies
    # ------------------------------------------------------------------

    def _event_body_path(self, origin: str, event_id: bytes) -> str:
        origin_hex = _safe_path_component(origin)
        return os.path.join(self._events_dir, origin_hex, "bodies", event_id.hex())

    def write_event_body(
        self,
        origin: str,
        event_id: bytes,
        body: bytes,
        expected_hash: bytes,
        expected_size: int,
    ) -> None:
        """Write an event body (non-article body) to its flat path."""
        if len(body) != expected_size:
            raise BodyError(f"event body size {len(body)} != expected {expected_size}")
        if compute_body_hash(body) != expected_hash:
            raise BodyError("event body hash mismatch")

        path = self._event_body_path(origin, event_id)
        with self._lock:
            self._atomic_write_verified(path, body, expected_hash, expected_size)

    def get_event_body(
        self,
        origin: str,
        event_id: bytes,
        expected_hash: bytes,
        expected_size: int,
    ) -> bytes | None:
        path = self._event_body_path(origin, event_id)
        with self._lock:
            if not os.path.exists(path):
                return None
            with open(path, "rb") as f:
                body = f.read()
            if len(body) != expected_size:
                return None
            if compute_body_hash(body) != expected_hash:
                return None
            return body

    def event_body_exists(self, origin: str, event_id: bytes) -> bool:
        return os.path.exists(self._event_body_path(origin, event_id))

    def delete_event_body(self, origin: str, event_id: bytes) -> bool:
        path = self._event_body_path(origin, event_id)
        with self._lock:
            if os.path.exists(path):
                os.remove(path)
                return True
            return False

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_staging(self, origin: str, board: str) -> int:
        """Remove orphaned staging files for a board. Returns count deleted."""
        origin_hex = _safe_path_component(origin)
        board_hex = _safe_path_component(board)
        staging_dir = os.path.join(self._boards_dir, origin_hex, board_hex, "bodies", "staging")
        count = 0
        with self._lock:
            if not os.path.isdir(staging_dir):
                return 0
            for name in os.listdir(staging_dir):
                path = os.path.join(staging_dir, name)
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                        count += 1
                except OSError:
                    pass
        return count

    # ------------------------------------------------------------------
    # Origin-scoped deletion (depeer/purge)
    # ------------------------------------------------------------------

    def delete_origin_bodies(self, origin: str) -> int:
        """Delete all article and event body files for an origin.

        Returns the total number of files deleted.
        """
        import shutil

        origin_hex = _safe_path_component(origin)
        count = 0
        with self._lock:
            boards_origin_dir = os.path.join(self._boards_dir, origin_hex)
            if os.path.isdir(boards_origin_dir):
                for root, dirs, files in os.walk(boards_origin_dir):
                    for name in files:
                        try:
                            os.remove(os.path.join(root, name))
                            count += 1
                        except OSError:
                            pass
                shutil.rmtree(boards_origin_dir, ignore_errors=True)

            events_origin_dir = os.path.join(self._events_dir, origin_hex)
            if os.path.isdir(events_origin_dir):
                for root, dirs, files in os.walk(events_origin_dir):
                    for name in files:
                        try:
                            os.remove(os.path.join(root, name))
                            count += 1
                        except OSError:
                            pass
                shutil.rmtree(events_origin_dir, ignore_errors=True)

        return count

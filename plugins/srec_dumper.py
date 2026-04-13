"""
srec_dumper - CDT Plugin
=========================
Captures ReadMemoryByAddress, WriteMemoryByAddress, RequestDownload,
and RequestUpload sessions from a decoded KWP trace and writes them as
Motorola SREC files via *hexrec*.  All commits are gated on the ECU's
positive response; NACKed requests are silently dropped.

Services handled
----------------
  0x23/0x63  ReadMemoryByAddress       request -> pending; 0x63 -> commit
  0x3D/0x7D  WriteMemoryByAddress      request -> pending; 0x7D -> commit
  0x34/0x74  RequestDownload           request -> pending; 0x74 -> open session
  0x35/0x75  RequestUpload             request -> pending; 0x75 -> open session
  0x36/0x76  TransferData              data block -> pending; 0x76 -> commit
  0x37/0x77  RequestTransferExit       0x37 -> no-op; 0x77 -> flush session

  For downloads (0x34) the tester sends 0x36 blocks (msg.tgt = ECU).
  For uploads   (0x35) the ECU   sends 0x36 blocks (msg.src = ECU).
  Both share the same 0x36/0x76/0x37/0x77 handlers; direction is inferred
  from which active-session dict the ECU address appears in.

Output: <prefix>_sNNNN_{read|write|dl|ul}_<START>_<END>.srec

Architecture
------------
  MemoryChunk      - address + data slice
  MemorySession    - ordered sequence of chunks; one logical session
  SessionCollector - stateful; maps KWP events to sessions with full ACK pairing
  SrecWriter       - pure I/O; converts sessions -> SREC files via hexrec
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger("cdt.plugins.srec_dumper")

try:
    from hexrec.formats.srec import Memory, SrecFile  # type: ignore[import-untyped]

    _HEXREC_OK = True
except ImportError:
    _HEXREC_OK = False


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class OpType(str, Enum):
    READ = "read"
    WRITE = "write"
    DOWNLOAD = "dl"
    UPLOAD = "ul"


@dataclass
class MemoryChunk:
    address: int
    data: bytes

    @property
    def end_address(self) -> int:
        return self.address + len(self.data)


@dataclass
class MemorySession:
    op_type: OpType
    chunks: list[MemoryChunk] = field(default_factory=list)
    seq: int = 0

    @property
    def start_address(self) -> int | None:
        return self.chunks[0].address if self.chunks else None

    @property
    def end_address(self) -> int | None:
        return (self.chunks[-1].end_address - 1) if self.chunks else None

    def is_empty(self) -> bool:
        return not self.chunks or all(not c.data for c in self.chunks)

    def try_append(self, chunk: MemoryChunk, max_gap: int) -> bool:
        """Append chunk if it fits within max_gap; reject on gap overflow or backward jump."""
        if not self.chunks:
            self.chunks.append(chunk)
            return True
        gap = chunk.address - self.chunks[-1].end_address
        if gap < 0 or gap > max_gap:
            return False
        self.chunks.append(chunk)
        return True


@dataclass
class _XferState:
    """Per-ECU state for an active download or upload TransferData sequence."""

    base_addr: int
    size: int
    chunks: list[bytes] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SessionCollector
# ---------------------------------------------------------------------------


class SessionCollector:
    """Maps KWP events to MemorySession objects with full request/response pairing.

    All pending-state dicts are keyed by ECU address so interleaved
    multi-ECU traces are handled without cross-contamination.
    """

    # KWP service IDs
    _S = {
        "rmba": 0x23,
        "rmba_r": 0x63,
        "wmba": 0x3D,
        "wmba_r": 0x7D,
        "rdl": 0x34,
        "rdl_r": 0x74,
        "rul": 0x35,
        "rul_r": 0x75,
        "td": 0x36,
        "td_r": 0x76,
        "te": 0x37,
        "te_r": 0x77,
    }

    def __init__(self, max_gap: int) -> None:
        self._max_gap = max_gap
        self._completed: list[MemorySession] = []
        self._seq: int = 0

        self._active_read: MemorySession | None = None
        self._active_write: MemorySession | None = None

        self._pending_rmba: dict[int, tuple[int, int]] = {}  # tgt -> (addr, size)
        self._pending_wmba: dict[int, list[MemoryChunk]] = {}  # tgt -> [chunks]
        self._pending_dl: dict[int, tuple[int, int]] = {}  # tgt -> (addr, size)
        self._pending_ul: dict[int, tuple[int, int]] = {}  # tgt -> (addr, size)
        self._active_dl: dict[int, _XferState] = {}  # src -> state
        self._active_ul: dict[int, _XferState] = {}  # src -> state
        self._pending_td: dict[int, list[bytes]] = {}  # ecu -> [blocks] (dl)
        self._pending_tu: dict[int, list[bytes]] = {}  # ecu -> [blocks] (ul)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def handle(self, msg: Any) -> None:
        fn = self._DISPATCH.get(msg.service_id)
        if fn:
            fn(self, msg)

    def flush_all(self) -> list[MemorySession]:
        """Close open read/write sessions; discard unfinished transfers."""
        self._close_rw(OpType.READ)
        self._close_rw(OpType.WRITE)
        for d in (
            self._active_dl,
            self._active_ul,
            self._pending_td,
            self._pending_tu,
            self._pending_dl,
            self._pending_ul,
            self._pending_wmba,
        ):
            d.clear()
        sessions, self._completed = self._completed, []
        return sessions

    # ------------------------------------------------------------------
    # ReadMemoryByAddress  0x23 / 0x63
    # ------------------------------------------------------------------

    def _on_rmba(self, msg: Any) -> None:
        addr = _addr(msg.params, "memoryAddress")
        size = _addr(msg.params, "memorySize")
        if addr is not None and size is not None:
            self._pending_rmba[msg.tgt] = (addr, size)

    def _on_rmba_r(self, msg: Any) -> None:
        pend = self._pending_rmba.pop(msg.src, None)
        if pend is None:
            return
        data = _data(msg.params, "dataRecord", "raw_payload")
        if data:
            self._push_rw(OpType.READ, MemoryChunk(pend[0], data))

    # ------------------------------------------------------------------
    # WriteMemoryByAddress  0x3D / 0x7D
    # ------------------------------------------------------------------

    def _on_wmba(self, msg: Any) -> None:
        addr = _addr(msg.params, "memoryAddress")
        data = _data(msg.params, "dataRecord", "raw_payload")
        if addr is not None and data:
            self._pending_wmba.setdefault(msg.tgt, []).append(MemoryChunk(addr, data))

    def _on_wmba_r(self, msg: Any) -> None:
        q = self._pending_wmba.get(msg.src)
        if not q:
            return
        self._push_rw(OpType.WRITE, q.pop(0))
        if not q:
            del self._pending_wmba[msg.src]

    # ------------------------------------------------------------------
    # RequestDownload  0x34 / 0x74
    # ------------------------------------------------------------------

    def _on_rdl(self, msg: Any) -> None:
        addr = _addr(msg.params, "memoryAddress")
        if addr is not None:
            size = _addr(msg.params, "memorySize") or 0
            self._pending_dl[msg.tgt] = (addr, size)

    def _on_rdl_r(self, msg: Any) -> None:
        pend = self._pending_dl.pop(msg.src, None)
        if pend:
            self._active_dl[msg.src] = _XferState(pend[0], pend[1])

    # ------------------------------------------------------------------
    # RequestUpload  0x35 / 0x75
    # ------------------------------------------------------------------

    def _on_rul(self, msg: Any) -> None:
        addr = _addr(msg.params, "memoryAddress")
        if addr is not None:
            size = _addr(msg.params, "memorySize") or 0
            self._pending_ul[msg.tgt] = (addr, size)

    def _on_rul_r(self, msg: Any) -> None:
        pend = self._pending_ul.pop(msg.src, None)
        if pend:
            self._active_ul[msg.src] = _XferState(pend[0], pend[1])

    # ------------------------------------------------------------------
    # TransferData  0x36 / 0x76  (shared by download and upload)
    #
    #   Download:  tester -> ECU  ->  msg.tgt = ECU addr
    #   Upload:    ECU -> tester  ->  msg.src = ECU addr
    # ------------------------------------------------------------------

    def _on_td(self, msg: Any) -> None:
        data = _data(msg.params, "dataRecord", "raw_payload")
        if not data:
            return
        if msg.tgt in self._active_dl:  # download block
            self._pending_td.setdefault(msg.tgt, []).append(data)
        elif msg.src in self._active_ul:  # upload block
            self._pending_tu.setdefault(msg.src, []).append(data)

    def _on_td_r(self, msg: Any) -> None:
        # Download ACK: ECU (msg.src) acks a block that was sent TO it
        if msg.src in self._active_dl:
            self._commit_block(self._pending_td, self._active_dl, msg.src)
        # Upload ACK: tester (msg.tgt) acks a block sent BY the ECU
        elif msg.tgt in self._active_ul:
            self._commit_block(self._pending_tu, self._active_ul, msg.tgt)

    def _commit_block(
        self,
        pending: dict[int, list[bytes]],
        active: dict[int, _XferState],
        ecu: int,
    ) -> None:
        q = pending.get(ecu)
        if not q:
            return
        session = active.get(ecu)
        if session:
            session.chunks.append(q.pop(0))
        else:
            q.pop(0)
        if not q:
            pending.pop(ecu, None)

    # ------------------------------------------------------------------
    # RequestTransferExit  0x37 / 0x77  (shared)
    # ------------------------------------------------------------------

    def _on_te(self, _msg: Any) -> None:
        pass  # no-op; finalization waits for positive response

    def _on_te_r(self, msg: Any) -> None:
        ecu = msg.src
        for active, pending, op in (
            (self._active_dl, self._pending_td, OpType.DOWNLOAD),
            (self._active_ul, self._pending_tu, OpType.UPLOAD),
        ):
            xfer = active.pop(ecu, None)
            pending.pop(ecu, None)
            if xfer:
                full = b"".join(xfer.chunks)
                if full:
                    self._completed.append(
                        MemorySession(
                            op_type=op,
                            chunks=[MemoryChunk(xfer.base_addr, full)],
                            seq=self._next_seq(),
                        )
                    )

    # ------------------------------------------------------------------
    # Read / Write helpers
    # ------------------------------------------------------------------

    def _push_rw(self, op: OpType, chunk: MemoryChunk) -> None:
        is_read = op is OpType.READ
        active = self._active_read if is_read else self._active_write

        if active is None or not active.try_append(chunk, self._max_gap):
            if active is not None:
                self._close_rw(op)
            active = MemorySession(op_type=op, seq=self._next_seq())
            active.try_append(chunk, self._max_gap)
            if is_read:
                self._active_read = active
            else:
                self._active_write = active

    def _close_rw(self, op: OpType) -> None:
        is_read = op is OpType.READ
        active = self._active_read if is_read else self._active_write
        if active and not active.is_empty():
            self._completed.append(active)
        if is_read:
            self._active_read = None
        else:
            self._active_write = None

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # Dispatch table populated below after class body
    _DISPATCH: dict[int, Any] = {}


_S = SessionCollector._S
SessionCollector._DISPATCH = {
    _S["rmba"]: SessionCollector._on_rmba,
    _S["rmba_r"]: SessionCollector._on_rmba_r,
    _S["wmba"]: SessionCollector._on_wmba,
    _S["wmba_r"]: SessionCollector._on_wmba_r,
    _S["rdl"]: SessionCollector._on_rdl,
    _S["rdl_r"]: SessionCollector._on_rdl_r,
    _S["rul"]: SessionCollector._on_rul,
    _S["rul_r"]: SessionCollector._on_rul_r,
    _S["td"]: SessionCollector._on_td,
    _S["td_r"]: SessionCollector._on_td_r,
    _S["te"]: SessionCollector._on_te,
    _S["te_r"]: SessionCollector._on_te_r,
}
del _S


# ---------------------------------------------------------------------------
# SrecWriter
# ---------------------------------------------------------------------------


class SrecWriter:
    """Converts MemorySession objects -> SREC files via hexrec.

    Uses a Memory sparse-map so overlapping reads (e.g. verification
    re-reads) are handled correctly: later data overwrites earlier data
    at the same address.
    """

    def __init__(self, output_dir: Path, prefix: str) -> None:
        self._dir = output_dir
        self._prefix = prefix
        output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, session: MemorySession) -> tuple[Path, int]:
        """Write session to .srec; return (path, bytes_written)."""
        start = session.start_address
        end = session.end_address
        s = f"{start:08X}" if start is not None else "00000000"
        e = f"{end:08X}" if end is not None else "00000000"
        path = (
            self._dir
            / f"{self._prefix}_s{session.seq:04d}_{session.op_type.value}_{s}_{e}.srec"
        )

        mem = Memory()
        for chunk in session.chunks:
            if chunk.data:
                mem.write(chunk.address, bytes(chunk.data))
        SrecFile.from_memory(mem).save(str(path))
        return path, mem.content_size


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _addr(params: dict[str, Any], key: str) -> int | None:
    """Extract an integer address / size from a params field (bytes/int/enum-dict)."""
    raw = params.get(key)
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return int.from_bytes(raw, "big")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, dict):
        v = raw.get("value")
        return int(v) if v is not None else None
    return None


def _data(params: dict[str, Any], *keys: str) -> bytes | None:
    """Concatenate bytes from one or more params fields; return None if nothing found."""
    parts: list[bytes] = []
    for key in keys:
        val = params.get(key)
        if val is None:
            continue
        if isinstance(val, (bytes, bytearray)):
            parts.append(bytes(val))
        elif isinstance(val, int):
            parts.append(bytes([val]))
        elif isinstance(val, dict) and "value" in val:
            inner = val["value"]
            parts.append(bytes([inner]) if isinstance(inner, int) else bytes(inner))
    return b"".join(parts) if parts else None


# ---------------------------------------------------------------------------
# Plugin state
# ---------------------------------------------------------------------------

_state: dict[str, Any] = {"collector": None, "writer": None}


# ---------------------------------------------------------------------------
# Plugin API
# ---------------------------------------------------------------------------


def add_arguments(parser: Any) -> None:
    """Register plugin-specific CLI arguments."""
    parser.add_argument(
        "--srec-output",
        metavar="DIR",
        help="[srec_dumper] Directory to write SREC files into.",
    )
    parser.add_argument(
        "--srec-prefix",
        default="dump",
        metavar="PREFIX",
        help="[srec_dumper] Filename prefix (default: dump).",
    )
    parser.add_argument(
        "--srec-gap",
        type=int,
        default=256,
        metavar="BYTES",
        help="[srec_dumper] Max address gap in a read/write session (default: 256).",
    )


def init(args: Any) -> None:
    """Validate arguments and set up collector + writer."""
    if not _HEXREC_OK:
        log.error("'hexrec' not found; run: pip install hexrec")
        return

    defs_path = getattr(args, "defs", None)
    if not defs_path or not Path(defs_path).is_file():
        msg = "not set" if not defs_path else f"not found: {defs_path}"
        log.error("--defs <file.json> %s", msg)
        sys.exit(2)

    output_dir = getattr(args, "srec_output", None)
    if not output_dir:
        log.warning("--srec-output not set; plugin disabled.")
        return

    prefix = getattr(args, "srec_prefix", "dump") or "dump"
    max_gap = getattr(args, "srec_gap", 256)

    _state["collector"] = SessionCollector(max_gap=max_gap)
    _state["writer"] = SrecWriter(Path(output_dir), prefix)
    log.info("Output: %r, prefix=%r, gap=%d", output_dir, prefix, max_gap)


def on_kwp_message(kwp_msg: Any) -> None:
    """Feed every decoded KWP message to the collector."""
    if _state["collector"]:
        _state["collector"].handle(kwp_msg)


def teardown() -> None:
    """Flush all open sessions and write SREC files."""
    collector: SessionCollector | None = _state["collector"]
    writer: SrecWriter | None = _state["writer"]
    if not collector or not writer:
        return

    sessions = collector.flush_all()
    if not sessions:
        log.info("No memory sessions found.")
        return

    n = 0
    for session in sorted(sessions, key=lambda s: s.seq):
        if session.is_empty():
            continue
        try:
            path, nb = writer.write(session)
            log.info("Wrote %s  (%d bytes)", path, nb)
            n += 1
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.error("seq=%d: %s", session.seq, exc)

    log.info("Done - %d SREC file(s) written.", n)

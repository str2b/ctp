"""CDT - CAN Diagnostic Tap. A modular streaming pipeline for CAN/ISOTP diagnostic analysis."""

import abc
import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import NamedTuple

import can
from scapy.all import Raw
from scapy.contrib.automotive.kwp import KWP


# ---------------------------------------------------------------------------
# Data classes - one per protocol layer
# ---------------------------------------------------------------------------

class Filterable(abc.ABC):
    """Interface for protocol layer objects that can be processed by FilterEngine."""

    @property
    @abc.abstractmethod
    def layer(self) -> str:
        """The protocol layer name (e.g. 'can', 'isotp', 'kwp')."""
        return ""

    @abc.abstractmethod
    def filter_attrs(self) -> dict:
        """Attributes exposed to FilterEngine for rule evaluation."""
        return {}


class CANFrame(Filterable):
    """Wraps a raw can.Message with a resolved direction field."""

    def __init__(self, arb_id, data, timestamp, direction):
        self.arb_id = arb_id
        self.data = data
        self.timestamp = timestamp
        self.direction = direction

    @property
    def layer(self) -> str:
        return "can"

    def filter_attrs(self) -> dict:
        return {"id": self.arb_id, "payload": self.data}


class ISOTPMessage(Filterable):
    """Carries a fully reassembled ISOTP data payload and its metadata."""

    def __init__(self, rx_id, tgt_addr, time, direction, data, can_frames=None):
        self.rx_id = rx_id
        self.tgt_addr = tgt_addr
        self.time = time
        self.direction = direction
        self.data = data
        self.can_frames = can_frames or []

    @property
    def layer(self) -> str:
        return "isotp"

    def filter_attrs(self) -> dict:
        return {"payload": self.data}


class KWPMessage(Filterable):
    """Carries a decoded KWP service message and its metadata."""

    def __init__(self, isotp_msg, service_hex, service_name, params, scapy_pkt=None):
        self.isotp_msg = isotp_msg
        self.src = isotp_msg.rx_id & 0xFF
        self.tgt = isotp_msg.tgt_addr
        self.time = isotp_msg.time
        self.direction = isotp_msg.direction
        self.service_hex = service_hex
        self.service_name = service_name
        self.params = params
        self.data = isotp_msg.data
        self._scapy_pkt = scapy_pkt

    @property
    def layer(self) -> str:
        return "kwp"

    @property
    def packet(self):
        """Uniform access to the Scapy KWP object (lazy-loaded if decoded via Defs)."""
        if self._scapy_pkt is None:
            self._scapy_pkt = KWP(self.data)
        return self._scapy_pkt

    def filter_attrs(self):
        """Attributes exposed to FilterEngine for rule evaluation."""
        return {
            "src": self.src,
            "tgt": self.tgt,
            "service": f"0x{self.service_hex:0X}",
            "payload": self.data,
        }


# ---------------------------------------------------------------------------
# FilterEngine
# ---------------------------------------------------------------------------

class FilterEngine:
    """Loads a JSON filter definition and evaluates frames against its rules."""

    def __init__(self, filter_file=None):
        self.mode = "whitelist"
        self.rules = []
        if not filter_file:
            return
        try:
            with open(filter_file, "r", encoding="utf-8") as f:
                filter_def = json.load(f)
            self.mode = filter_def.get("mode", "whitelist").lower()
            self.rules = filter_def.get("rules", [])
            print(
                f"Loaded {len(self.rules)} core filter rules in {self.mode} mode.",
                file=sys.stderr,
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"Failed to load filter file {filter_file}: {e}", file=sys.stderr)
            sys.exit(1)

    def should_drop(self, message: Filterable):
        """Returns True if the message should be discarded according to the filter rules."""
        if not self.rules:
            return False

        layer = message.layer
        layer_rules = [r for r in self.rules if r.get("layer", "").lower() == layer]
        if not layer_rules:
            return False

        attrs = message.filter_attrs()
        rule_matched = False
        for rule in layer_rules:
            rule_matches = True
            for key, expected_val in rule.items():
                if key == "layer":
                    continue
                val = attrs.get(key)
                if val is None:
                    rule_matches = False
                    break
                if key == "payload":
                    if not isinstance(val, (bytes, bytearray)):
                        rule_matches = False
                        break
                    if not re.search(str(expected_val), val.hex().upper(), re.IGNORECASE):
                        rule_matches = False
                        break
                else:
                    str_val = (
                        f"0X{val:0X}" if isinstance(val, int) else str(val).upper()
                    )
                    exp_val_str = str(expected_val).upper()
                    if str_val != exp_val_str and exp_val_str != str(val):
                        rule_matches = False
                        break
            if rule_matches:
                rule_matched = True
                break

        return not rule_matched if self.mode == "whitelist" else rule_matched


# ---------------------------------------------------------------------------
# DefsEngine
# ---------------------------------------------------------------------------

class DefsEngine:
    """Loads a custom JSON service definition file and provides lookup and payload parsing."""

    def __init__(self, defs_file=None):
        self.defs = {}
        if not defs_file:
            return
        try:
            with open(defs_file, "r", encoding="utf-8") as f:
                self.defs = json.load(f)
            print(f"Loaded custom definitions from {defs_file}", file=sys.stderr)
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"Failed to load defs file {defs_file}: {e}", file=sys.stderr)

    def lookup(self, service_id, base_info=None):
        """Returns (service_def, service_name) for a service ID, or (None, None).
        Supports dicts or lists of dicts for a service. Matches based on 'src' and 'tgt'."""
        services_dict = self.defs.get("services", self.defs)
        hex_key = f"0x{service_id:02X}"
        service_entry = services_dict.get(hex_key) or services_dict.get(str(service_id))
        
        if not service_entry:
            return None, None

        candidates = service_entry if isinstance(service_entry, list) else [service_entry]
        best_match = None
        best_score = -1
        
        msg_src = base_info.get("src") if base_info else None
        msg_tgt = base_info.get("tgt") if base_info else None

        for cand in candidates:
            score = 0
            cand_src = cand.get("src")
            cand_tgt = cand.get("tgt")
            
            if cand_src is not None:
                cand_src_val = int(cand_src, 16) if isinstance(cand_src, str) and cand_src.lower().startswith("0x") else int(cand_src)
                if msg_src is not None and cand_src_val == msg_src:
                    score += 1
                else:
                    continue  # strict mismatch
                    
            if cand_tgt is not None:
                cand_tgt_val = int(cand_tgt, 16) if isinstance(cand_tgt, str) and cand_tgt.lower().startswith("0x") else int(cand_tgt)
                if msg_tgt is not None and cand_tgt_val == msg_tgt:
                    score += 1
                else:
                    continue  # strict mismatch
            
            if score > best_score:
                best_score = score
                best_match = cand

        if best_match:
            return best_match, best_match.get("name", f"CustomService_{hex_key}")
            
        return None, None

    def parse_payload(self, payload_bytes, base_info):
        """Maps payload bytes to named parameters using JSON definitions."""
        if not self.defs or len(payload_bytes) < 1:
            return None

        service_def, service_name = self.lookup(payload_bytes[0], base_info)
        if not service_def:
            return None

        base_info["service_name"] = service_name
        args_layout = service_def.get("args") or {}
        layout = args_layout.get(str(len(payload_bytes)), args_layout.get("default", []))

        params_dict = {}
        offset = 1
        layout_queue = list(layout)

        while layout_queue:
            param = layout_queue.pop(0)

            if "mux" in param:
                expanded = self._resolve_mux(param, params_dict)
                if expanded:
                    layout_queue = expanded + layout_queue
                continue

            if offset >= len(payload_bytes):
                break

            name, value, offset = self._decode_param(param, payload_bytes, offset)
            params_dict[name] = value

        if offset < len(payload_bytes):
            params_dict["trailing_payload"] = payload_bytes[offset:]

        base_info["params"] = params_dict
        return base_info

    @staticmethod
    def _resolve_mux(param, params_dict):
        """Resolve a mux entry against already-parsed params. Returns the matched case list or None."""
        switch_on = param.get("switch_on")
        if not switch_on:
            return None
        prev_val = params_dict.get(switch_on)
        if prev_val is None:
            return None
        if isinstance(prev_val, dict):
            int_val = prev_val.get("value")
        elif isinstance(prev_val, int):
            int_val = prev_val
        elif isinstance(prev_val, (bytes, bytearray)):
            int_val = int.from_bytes(prev_val, byteorder="big")
        else:
            return None
        cases = param["mux"]
        matched = (
            cases.get(f"0x{int_val:02X}")
            or cases.get(str(int_val))
            or cases.get("default")
        )
        return matched if isinstance(matched, list) else None

    @staticmethod
    def _decode_param(param, payload_bytes, offset):
        """Read one parameter from payload_bytes at offset. Returns (name, value, new_offset)."""
        p_name = param.get("name", "unknown")
        p_len = param.get("length", 1)

        if p_len == -1:
            raw_val = payload_bytes[offset:]
            offset = len(payload_bytes)
        else:
            raw_val = payload_bytes[offset: offset + p_len]
            offset += p_len

        if not (0 < p_len <= 8):
            return p_name, raw_val, offset

        int_val = int.from_bytes(raw_val, byteorder="big")
        named_val = DefsEngine._lookup_enum(param.get("enum", {}), int_val)

        if named_val:
            return p_name, {"value": int_val, "name": named_val}, offset
        if p_len == 1:
            return p_name, int_val, offset
        return p_name, raw_val, offset

    @staticmethod
    def _lookup_enum(enum_map, int_val):
        """Return the enum label for int_val, supporting exact and range keys. Returns None if not found."""
        named = enum_map.get(f"0x{int_val:02X}") or enum_map.get(str(int_val))
        if named:
            return named
        for k, v in enum_map.items():
            if isinstance(k, str) and "-" in k:
                try:
                    lo, hi = k.split("-", 1)
                    if int(lo.strip(), 0) <= int_val <= int(hi.strip(), 0):
                        return v
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
        return None


# ---------------------------------------------------------------------------
# ISOTPReassembler
# ---------------------------------------------------------------------------

class _ISOTPFrame(NamedTuple):
    """Addressing-resolved view of a CAN frame, ready for ISOTP processing."""
    rx_id: int
    target_addr: int
    isotp_payload: bytes
    session_key: object
    timestamp: float
    direction: str
    frame_entry: tuple


class ISOTPReassembler:
    """Stateful ISOTP session reassembler. Consumes CANFrames, yields ISOTPMessage on completion."""

    def __init__(self, addressing="standard", physical_ids=None, functional_ids=None,
                 session_timeout=2.0):
        self.addressing = addressing.lower()
        self.session_timeout = session_timeout  # seconds; 0 disables timeout eviction
        self._sessions = {}
        self._id_to_target = {}
        self._use_custom_ids = physical_ids is not None or functional_ids is not None
        self._diagnostic_ids = set()
        for ids_list in (physical_ids, functional_ids):
            if not ids_list:
                continue
            for rxid in ids_list:
                try:
                    parsed = int(rxid, 16) if rxid.lower().startswith("0x") else int(rxid)
                    self._diagnostic_ids.add(parsed)
                except Exception:  # pylint: disable=broad-exception-caught
                    pass

    def is_isotp_id(self, arb_id):
        """Returns True if this arb_id should be treated as an ISOTP frame."""
        if self._use_custom_ids:
            return arb_id in self._diagnostic_ids
        if 0x600 <= arb_id <= 0x6FF:
            return True
        if 0x7DF <= arb_id <= 0x7EF:
            return True
        if arb_id & 0x00FFFF00 in (0x00DA0000, 0x00DB0000):
            return True
        return False

    def process(self, can_frame):
        """Process a CANFrame. Returns an ISOTPMessage on reassembly completion, or None."""
        frame = self._extract_addressing(can_frame)
        if frame is None:
            return None

        self._evict_stale(frame.timestamp)

        pci = frame.isotp_payload[0] >> 4
        if pci == 0: return self._handle_sf(frame)
        if pci == 1: self._handle_ff(frame)
        if pci == 2: return self._handle_cf(frame)
        if pci == 3: self._handle_fc(frame)
        return None

    def _extract_addressing(self, can_frame):
        """Resolve addressing fields from a CANFrame based on the configured mode.

        Returns an _ISOTPFrame or None if the frame is invalid.
        """
        payload = can_frame.data
        arb_id = can_frame.arb_id
        timestamp = can_frame.timestamp
        direction = can_frame.direction

        if not payload:
            return None

        if self.addressing == "extended":
            if len(payload) < 2:
                return None
            target_addr = payload[0]
            self._id_to_target[arb_id] = target_addr
            isotp_payload = payload[1:]
            session_key = (arb_id, target_addr)
        else:
            target_addr = self._id_to_target.get(arb_id, 0xFF)
            isotp_payload = payload
            session_key = arb_id

        if not isotp_payload:
            return None

        return _ISOTPFrame(
            rx_id=arb_id,
            target_addr=target_addr,
            isotp_payload=isotp_payload,
            session_key=session_key,
            timestamp=timestamp,
            direction=direction,
            frame_entry=(timestamp, direction, arb_id, payload),
        )

    def _evict_stale(self, timestamp):
        """Remove sessions that have exceeded the inactivity timeout."""
        if self.session_timeout <= 0:
            return
        stale = [k for k, v in self._sessions.items()
                 if timestamp - v["started"] > self.session_timeout]
        for k in stale:
            del self._sessions[k]

    def _handle_sf(self, frame: _ISOTPFrame):
        """Handle a Single Frame (PCI=0). Returns ISOTPMessage or None."""
        max_sf_dl = 7 if self.addressing == "standard" else 6
        dl = frame.isotp_payload[0] & 0x0F
        if not (0 < dl <= len(frame.isotp_payload) - 1) or dl > max_sf_dl:
            return None
        extracted = frame.isotp_payload[1: 1 + dl]
        padding = frame.isotp_payload[1 + dl:]
        if padding and (len(set(padding)) > 1 or padding[0] not in (0x00, 0x55, 0xAA, 0xCC, 0xFF)):
            return None
        return ISOTPMessage(frame.rx_id, frame.target_addr, frame.timestamp,
                            frame.direction, bytes(extracted), [frame.frame_entry])

    def _handle_ff(self, frame: _ISOTPFrame):
        """Handle a First Frame (PCI=1). Opens a new reassembly session."""
        max_sf_dl = 7 if self.addressing == "standard" else 6
        if len(frame.isotp_payload) < 2:
            return
        dl = ((frame.isotp_payload[0] & 0x0F) << 8) | frame.isotp_payload[1]
        if dl > max_sf_dl:
            self._sessions[frame.session_key] = {
                "dl": dl,
                "data": bytearray(frame.isotp_payload[2:]),
                "sn": 1,
                "started": frame.timestamp,
                "can_frames": [frame.frame_entry],
            }

    def _handle_cf(self, frame: _ISOTPFrame):
        """Handle a Consecutive Frame (PCI=2). Returns ISOTPMessage on completion or None."""
        if frame.session_key not in self._sessions:
            return None
        sess = self._sessions[frame.session_key]
        sn = frame.isotp_payload[0] & 0x0F
        if sn != sess["sn"]:
            del self._sessions[frame.session_key]
            return None
        sess["data"].extend(frame.isotp_payload[1:])
        sess["sn"] = (sn + 1) & 0x0F
        sess["can_frames"].append(frame.frame_entry)
        if len(sess["data"]) >= sess["dl"]:
            full_data = bytes(sess["data"][: sess["dl"]])
            frames = sess["can_frames"]
            del self._sessions[frame.session_key]
            return ISOTPMessage(frame.rx_id, frame.target_addr, frame.timestamp,
                                frame.direction, full_data, frames)
        return None

    @staticmethod
    def _handle_fc(_frame: _ISOTPFrame):
        """Handle a Flow Control frame (PCI=3). Transport handshake, no application data."""

    def reset(self):
        """Clears all active reassembly sessions (call before each analyze pass)."""
        self._sessions.clear()
        self._id_to_target.clear()


# ---------------------------------------------------------------------------
# Protocol Layer - registry pattern, multiple decoders active simultaneously
#
#   ProtocolDecoder (ABC)
#    KWPDecoder   (KWP2000 / ISO 14230)
#
#   ProtocolRegistry   tries each decoder in order, dispatches first match
# ---------------------------------------------------------------------------

class ProtocolDecoder(abc.ABC):
    """Decodes ISOTPMessages into typed application-layer protocol messages."""

    @abc.abstractmethod
    def process(self, isotp_msg: ISOTPMessage) -> "Filterable | None":
        """Return a decoded protocol message, or None if not applicable."""


class ProtocolRegistry:
    """Tries each ProtocolDecoder in order; dispatches the first successful result."""

    def __init__(self):
        self._decoders: list[ProtocolDecoder] = []

    def register(self, decoder: ProtocolDecoder) -> "ProtocolRegistry":
        """Add a decoder and return self for fluent chaining."""
        self._decoders.append(decoder)
        return self

    def process(self, isotp_msg: ISOTPMessage) -> "Filterable | None":
        for decoder in self._decoders:
            result = decoder.process(isotp_msg)
            if result is not None:
                return result
        return None


class KWPDecoder(ProtocolDecoder):
    """Decodes KWP messages from ISOTPMessage payloads.

    Tries DefsEngine first for fast custom-JSON decoding; falls back to Scapy
    transparently. Always returns a KWPMessage - the caller never sees raw dicts
    or Scapy internals.
    """

    def __init__(self, defs_engine):
        self.defs = defs_engine

    def process(self, isotp_msg):
        """Decode an ISOTPMessage as KWP. Returns KWPMessage or None if not decodable."""
        data = isotp_msg.data
        if len(data) < 1 or data[0] not in range(0x10, 0xFF):
            return None

        try:
            base_info = {
                "src": isotp_msg.rx_id & 0xFF,
                "tgt": isotp_msg.tgt_addr,
                "service_hex": data[0],
                "service_name": "",
                "params": {},
            }

            defs_info = self.defs.parse_payload(data, base_info)
            if defs_info:
                return KWPMessage(
                    isotp_msg=isotp_msg,
                    service_hex=defs_info["service_hex"],
                    service_name=defs_info["service_name"],
                    params=defs_info["params"],
                    scapy_pkt=None,
                )

            # Scapy fallback
            scapy_pkt = KWP(data)
            service_hex, service_name, params = self._decode_via_scapy(scapy_pkt, base_info)
            return KWPMessage(
                isotp_msg=isotp_msg,
                service_hex=service_hex,
                service_name=service_name,
                params=params,
                scapy_pkt=scapy_pkt,
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(
                f"Error decoding KWP 0x{data[0]:02X} on 0x{isotp_msg.rx_id:X}: {e}",
                file=sys.stderr,
            )
            return None

    def _decode_via_scapy(self, kwp_pkt, base_info):
        """Extract service id, name, and params dict from a Scapy KWP packet."""
        service_hex = kwp_pkt.fields.get("service", 0)
        service_name = kwp_pkt.sprintf("%KWP.service%")

        if service_name.startswith("0x") or service_name.isdigit():
            req_name = None
            if isinstance(service_hex, int) and service_hex > 0x40:
                req_id = service_hex - 0x40
                _, req_name = self.defs.lookup(req_id, base_info)
                if not req_name:
                    try:
                        candidate = KWP(bytes([req_id])).sprintf("%KWP.service%")
                        if not (candidate.startswith("0x") or candidate.isdigit()):
                            req_name = candidate
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass
            service_name = f"{req_name}PositiveResponse" if req_name else "<Unknown_Service>"

        params = {}
        if kwp_pkt.payload:
            for k, v in kwp_pkt.payload.fields.items():
                if isinstance(v, int):
                    field_obj = kwp_pkt.payload.get_field(k)
                    if field_obj:
                        repr_val = str(field_obj.i2repr(kwp_pkt.payload, v))
                        if repr_val.startswith("'") and repr_val.endswith("'"):
                            repr_val = repr_val[1:-1]
                        if repr_val and not repr_val.isdigit() and not repr_val.lower().startswith("0x"):
                            params[k] = {"value": v, "name": repr_val}
                        else:
                            params[k] = v
                    else:
                        params[k] = v
                else:
                    params[k] = v
            if kwp_pkt.haslayer(Raw):
                raw_bytes = getattr(kwp_pkt.getlayer(Raw), "load", b"")
                if raw_bytes:
                    params["raw_payload" if not params else "trailing_payload"] = raw_bytes

        return service_hex, service_name, params


# ---------------------------------------------------------------------------
# Plugin Registry - fan-out pattern, all plugins receive every event
#
#   PluginRegistry
#    load(path)            dynamically imports a plugin module
#    add_arguments(parser) lets plugins register their own CLI args
#    init(args)            initializes all plugins after arg parsing
#    dispatch(msg)         calls on_{layer}_message(msg) on each plugin
#    teardown()            graceful shutdown for all plugins
# ---------------------------------------------------------------------------

class PluginRegistry:
    """Loads plugin modules and fans out protocol events to all of them."""

    def __init__(self):
        self._plugins = []

    def load(self, path: str) -> "PluginRegistry":
        """Dynamically load a plugin from a file path. Returns self for chaining."""
        abs_path = os.path.abspath(path)
        name = f"cdt_plugin_{len(self._plugins)}"
        spec = importlib.util.spec_from_file_location(name, abs_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self._plugins.append(mod)
        print(f"Loaded plugin: {path}", file=sys.stderr)
        return self

    def add_arguments(self, parser):
        """Let each plugin register its own CLI arguments."""
        for plugin in self._plugins:
            if hasattr(plugin, "add_arguments"):
                plugin.add_arguments(parser)

    def init(self, args):
        """Initialize all plugins after CLI argument parsing."""
        for plugin in self._plugins:
            if hasattr(plugin, "init"):
                plugin.init(args)

    def teardown(self):
        """Tear down all plugins in load order."""
        for plugin in self._plugins:
            if hasattr(plugin, "teardown"):
                plugin.teardown()

    def dispatch(self, msg: Filterable):
        """Call on_{layer}_message(msg) on every plugin that implements it."""
        handler = f"on_{msg.layer}_message"
        for plugin in self._plugins:
            fn = getattr(plugin, handler, None)
            if fn:
                fn(msg)


# ---------------------------------------------------------------------------
# TraceAnalyzer - pure pipeline orchestrator
# ---------------------------------------------------------------------------

class TraceAnalyzer:
    """Orchestrates the CAN -> ISOTP -> Protocol pipeline over a file or live bus."""

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        trace_file=None,
        interface=None,
        channel=None,
        bitrate=None,
        addressing="standard",
        filter_file=None,
        physical_ids=None,
        functional_ids=None,
        protocols=None,
        plugins=None,
    ):
        self.trace_file = trace_file
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate

        self.filter = FilterEngine(filter_file)
        self.reassembler = ISOTPReassembler(addressing, physical_ids, functional_ids)
        self.protocols = protocols or ProtocolRegistry()
        self.plugins = plugins or PluginRegistry()

        self.can_count = 0
        self.isotp_count = 0
        self.protocol_count = 0

    def analyze(self):
        """Open the data source and run the full protocol pipeline until exhausted."""
        reader = self._open_source()
        self.reassembler.reset()
        self.can_count = self.isotp_count = self.protocol_count = 0

        try:
            for raw_msg in reader:
                if raw_msg.is_error_frame or raw_msg.is_remote_frame:
                    continue

                #  CAN layer 
                self.can_count += 1
                direction = "Rx" if raw_msg.is_rx else "Tx"
                can_frame = CANFrame(
                    raw_msg.arbitration_id, raw_msg.data, raw_msg.timestamp, direction
                )

                if self.filter.should_drop(can_frame):
                    continue

                self.plugins.dispatch(can_frame)

                #  ISOTP layer 
                if not self.reassembler.is_isotp_id(can_frame.arb_id):
                    continue

                isotp_msg = self.reassembler.process(can_frame)
                if not isotp_msg:
                    continue

                self.isotp_count += 1
                if self.filter.should_drop(isotp_msg):
                    continue

                self.plugins.dispatch(isotp_msg)

                #  Protocol layer 
                proto_msg = self.protocols.process(isotp_msg)
                if not proto_msg:
                    continue

                if self.filter.should_drop(proto_msg):
                    continue

                self.protocol_count += 1
                self.plugins.dispatch(proto_msg)

        except KeyboardInterrupt:
            print("\nCapture interrupted by user.", file=sys.stderr)

        print(
            f"Processed {self.can_count} CAN frames,"
            f" yielding {self.isotp_count} ISOTPs and {self.protocol_count} protocol messages.",
            file=sys.stderr,
        )

    def _open_source(self):
        """Open and return a CAN message iterator (live bus or trace file reader)."""
        if self.interface:
            print(
                f"Opening LIVE interface '{self.interface}'"
                f" on channel '{self.channel}'...",
                file=sys.stderr,
            )
            kwargs = {"interface": self.interface, "channel": self.channel}
            if self.bitrate:
                kwargs["bitrate"] = self.bitrate
            return can.Bus(**kwargs)

        if not self.trace_file:
            raise ValueError("Specify a trace_file or a live --interface (with --channel).")

        # Auto-detect trace format by extension
        ext = Path(self.trace_file).suffix.lower()
        reader_map = {
            ".asc": can.ASCReader,
            ".blf": can.BLFReader,
        }

        if ext not in reader_map:
            raise ValueError(
                f"Unsupported trace format: {ext}. Supported: {', '.join(reader_map.keys())}"
            )

        print(
            f"Reading {self.trace_file} (format: {ext[1:].upper()}) in real-time streaming mode...",
            file=sys.stderr,
        )
        return reader_map[ext](self.trace_file)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def setup_parser():
    """Build and return the core argument parser."""
    parser = argparse.ArgumentParser(
        description="Python-based CAN Trace Analyzer using Scapy"
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "-t", "--trace",
        dest="trace_file",
        help="Path to the .asc or .blf trace file to analyze.",
    )
    source_group.add_argument(
        "-i", "--interface",
        help="Live python-can interface (e.g., 'pcan', 'socketcan', 'vector').",
    )

    live_group = parser.add_argument_group(
        "live options", "Arguments only applicable when using --interface."
    )
    live_group.add_argument(
        "-c", "--channel",
        help="python-can channel (e.g., 'vcan0', 'PCAN_USBBUS1').",
    )
    live_group.add_argument(
        "-b", "--bitrate", type=int,
        help="Bitrate for the live interface (e.g., 500000).",
    )

    parser.add_argument(
        "-a", "--addressing", choices=["standard", "extended"], default="extended",
        help="Type of ISOTP addressing layer (default: extended).",
    )
    parser.add_argument(
        "-d", "--defs",
        help="Optional JSON file defining custom service layouts to override Scapy.",
    )
    parser.add_argument(
        "-f", "--filter",
        help="Optional JSON filter engine configuration to dynamically route and drop payloads.",
    )
    parser.add_argument(
        "-p", "--protocols", nargs="+", default=["kwp"],
        choices=["kwp", "uds"],
        help="Protocols to decode (default: kwp). UDS is not yet implemented.",
    )
    parser.add_argument(
        "-pids", "--physical-ids", nargs="+",
        help="Optional list of physical CAN Arbitration IDs (hex or decimal).",
    )
    parser.add_argument(
        "-fids", "--functional-ids", nargs="+",
        help="Optional list of functional CAN Arbitration IDs (hex or decimal)."
             "to natively parse as ISO-TP.",
    )
    _add_plugin_argument(parser)
    return parser


def _add_plugin_argument(parser):
    """Add the plugin argument to a parser."""
    parser.add_argument(
        "-P", "--plugin", nargs="+", default=[],
        metavar="FILE",
        help="One or more Python plugin files (e.g. plugins/trace_printer.py).",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Build the plugin registry, parse arguments, assemble the pipeline, and run."""
    # Pre-parse to discover plugins before the main parser enforces required args.
    # Plugins may call add_arguments() to register their own flags.
    pre_parser = argparse.ArgumentParser(add_help=False)
    _add_plugin_argument(pre_parser)
    pre_args, _ = pre_parser.parse_known_args()

    plugins = PluginRegistry()
    for path in pre_args.plugin:
        try:
            plugins.load(path)
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"Failed to load plugin {path}: {e}", file=sys.stderr)

    arg_parser = setup_parser()
    plugins.add_arguments(arg_parser)
    args = arg_parser.parse_args()

    if args.interface:
        if not args.channel:
            arg_parser.error("--channel is required when using --interface.")
    else:
        if args.channel:
            arg_parser.error("--channel can only be used with --interface.")
        if args.bitrate:
            arg_parser.error("--bitrate can only be used with --interface.")

    protocols = ProtocolRegistry()
    if "kwp" in args.protocols:
        protocols.register(KWPDecoder(DefsEngine(args.defs)))
    if "uds" in args.protocols:
        print("UDS decoder not yet implemented.", file=sys.stderr)

    plugins.init(args)

    try:
        TraceAnalyzer(
            trace_file=args.trace_file,
            interface=args.interface,
            channel=args.channel,
            bitrate=args.bitrate,
            addressing=args.addressing,
            filter_file=args.filter,
            physical_ids=getattr(args, "physical_ids", None),
            functional_ids=getattr(args, "functional_ids", None),
            protocols=protocols,
            plugins=plugins,
        ).analyze()
    finally:
        plugins.teardown()


if __name__ == "__main__":
    main()

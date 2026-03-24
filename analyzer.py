"""CAN Trace Analyzer — a modular streaming pipeline for CAN/ISOTP/KWP analysis."""

import argparse
import re
import sys
import json
import importlib.util
import os
import can
from scapy.all import Raw
from scapy.contrib.automotive.kwp import KWP


# ---------------------------------------------------------------------------
# Data classes — one per protocol layer
# ---------------------------------------------------------------------------

class CANFrame:
    """Wraps a raw can.Message with a resolved direction field."""
    layer = "can"

    def __init__(self, arb_id, data, timestamp, direction):
        self.arb_id = arb_id
        self.data = data
        self.timestamp = timestamp
        self.direction = direction

    def filter_attrs(self):
        """Attributes exposed to FilterEngine for rule evaluation."""
        return {"id": self.arb_id, "payload": self.data}


class ISOTPMessage:
    """Carries a fully reassembled ISOTP data payload and its metadata."""
    layer = "isotp"

    def __init__(self, rx_id, tgt_addr, time, direction, data, can_frames=None):
        self.rx_id = rx_id
        self.tgt_addr = tgt_addr
        self.time = time
        self.direction = direction
        self.data = data
        self.can_frames = can_frames or []

    def filter_attrs(self):
        """Attributes exposed to FilterEngine for rule evaluation."""
        return {"payload": self.data}


class KWPMessage:
    """Carries a decoded KWP service message and its metadata."""
    layer = "kwp"

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

    def should_drop(self, message):
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
                    str_val = f"0x{val:0X}" if isinstance(val, int) else str(val).upper()
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

    def lookup(self, service_id):
        """Returns (service_def, service_name) for a service ID, or (None, None)."""
        services_dict = self.defs.get("services", self.defs)
        hex_key = f"0x{service_id:02X}"
        service_def = services_dict.get(hex_key) or services_dict.get(str(service_id))
        if service_def:
            return service_def, service_def.get("name", f"CustomService_{hex_key}")
        return None, None

    def parse_payload(self, payload_bytes, base_info):
        """Maps payload bytes to named parameters using JSON definitions. Returns enriched info or None."""
        if not self.defs or len(payload_bytes) < 1:
            return None

        service_def, service_name = self.lookup(payload_bytes[0])
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
                switch_on = param.get("switch_on")
                if not switch_on:
                    continue
                prev_val = params_dict.get(switch_on)
                if prev_val is None:
                    continue
                if isinstance(prev_val, dict):
                    int_val = prev_val.get("value")
                elif isinstance(prev_val, int):
                    int_val = prev_val
                elif isinstance(prev_val, (bytes, bytearray)):
                    int_val = int.from_bytes(prev_val, byteorder="big")
                else:
                    continue
                hex_val_str = f"0x{int_val:02X}"
                cases = param["mux"]
                matched_mux = (
                    cases.get(hex_val_str)
                    or cases.get(str(int_val))
                    or cases.get("default")
                )
                if matched_mux and isinstance(matched_mux, list):
                    layout_queue = matched_mux + layout_queue
                continue

            p_name = param.get("name", "unknown")
            p_len = param.get("length", 1)
            if offset >= len(payload_bytes):
                break

            if p_len == -1:
                raw_val = payload_bytes[offset:]
                offset = len(payload_bytes)
            else:
                raw_val = payload_bytes[offset: offset + p_len]
                offset += p_len

            if 0 < p_len <= 8:
                int_val = int.from_bytes(raw_val, byteorder="big")
                hex_val_str = f"0x{int_val:02X}"
                enum_map = param.get("enum", {})
                named_val = enum_map.get(hex_val_str) or enum_map.get(str(int_val))
                if not named_val:
                    for k, v in enum_map.items():
                        if isinstance(k, str) and "-" in k:
                            try:
                                lo, hi = k.split("-", 1)
                                if int(lo.strip(), 0) <= int_val <= int(hi.strip(), 0):
                                    named_val = v
                                    break
                            except Exception:  # pylint: disable=broad-exception-caught
                                pass
                if named_val:
                    params_dict[p_name] = {"value": int_val, "name": named_val}
                elif p_len == 1:
                    params_dict[p_name] = int_val
                else:
                    params_dict[p_name] = raw_val
            else:
                params_dict[p_name] = raw_val

        if offset < len(payload_bytes):
            params_dict["trailing_payload"] = payload_bytes[offset:]

        base_info["params"] = params_dict
        return base_info


# ---------------------------------------------------------------------------
# ISOTPReassembler
# ---------------------------------------------------------------------------

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

    def process(self, can_frame):  # pylint: disable=too-many-return-statements
        """Process a CANFrame. Returns an ISOTPMessage on reassembly completion, or None."""
        payload = can_frame.data
        arb_id = can_frame.arb_id
        timestamp = can_frame.timestamp
        direction = can_frame.direction

        if len(payload) == 0:
            return None

        if self.addressing == "extended":
            if len(payload) < 2:
                return None
            target_addr = payload[0]
            self._id_to_target[arb_id] = target_addr
            isotp_payload = payload[1:]
            session_key = (arb_id, target_addr)
            rx_id = arb_id
        else:
            target_addr = self._id_to_target.get(arb_id, 0xFF)
            isotp_payload = payload
            session_key = arb_id
            rx_id = arb_id

        if len(isotp_payload) == 0:
            return None

        if self.session_timeout > 0:
            stale = [
                k for k, v in self._sessions.items()
                if timestamp - v["started"] > self.session_timeout
            ]
            for k in stale:
                del self._sessions[k]

        pci = isotp_payload[0] >> 4
        can_frame_entry = (timestamp, direction, arb_id, payload)
        max_sf_dl = 7 if self.addressing == "standard" else 6

        if pci == 0:
            # Single Frame
            dl = isotp_payload[0] & 0x0F
            if 0 < dl <= len(isotp_payload) - 1:
                if dl > max_sf_dl:
                    return None
                extracted = isotp_payload[1: 1 + dl]
                padding = isotp_payload[1 + dl:]
                if len(padding) > 0:
                    if len(set(padding)) > 1:
                        return None
                    if padding[0] not in (0x00, 0x55, 0xAA, 0xCC, 0xFF):
                        return None
                return ISOTPMessage(
                    rx_id, target_addr, timestamp, direction, bytes(extracted), [can_frame_entry]
                )

        elif pci == 1:
            # First Frame
            if len(isotp_payload) >= 2:
                dl = ((isotp_payload[0] & 0x0F) << 8) | isotp_payload[1]
                if dl > max_sf_dl:
                    self._sessions[session_key] = {
                        "dl": dl,
                        "data": bytearray(isotp_payload[2:]),
                        "sn": 1,
                        "started": timestamp,
                        "can_frames": [can_frame_entry],
                    }

        elif pci == 2:
            # Consecutive Frame
            if session_key in self._sessions:
                sn = isotp_payload[0] & 0x0F
                if sn == self._sessions[session_key]["sn"]:
                    self._sessions[session_key]["data"].extend(isotp_payload[1:])
                    self._sessions[session_key]["sn"] = (sn + 1) & 0x0F
                    self._sessions[session_key]["can_frames"].append(can_frame_entry)
                    sess = self._sessions[session_key]
                    if len(sess["data"]) >= sess["dl"]:
                        full_data = bytes(sess["data"][: sess["dl"]])
                        frames = sess["can_frames"]
                        del self._sessions[session_key]
                        return ISOTPMessage(
                            rx_id, target_addr, timestamp, direction, full_data, frames
                        )
                else:
                    del self._sessions[session_key]

        elif pci == 3:
            # Flow Control — transport handshake, carries no application data.
            # Silently consumed here, same as a proper ISOTP stack would do.
            pass

        return None

    def reset(self):
        """Clears all active reassembly sessions (call before each analyze pass)."""
        self._sessions.clear()
        self._id_to_target.clear()


# ---------------------------------------------------------------------------
# KWPDecoder
# ---------------------------------------------------------------------------

class KWPDecoder:
    """Decodes KWP messages from ISOTPMessage payloads.

    Tries DefsEngine first for fast custom-JSON decoding; falls back to Scapy
    transparently. Always returns a KWPMessage — the caller never sees raw dicts
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
            service_hex, service_name, params = self._decode_via_scapy(scapy_pkt)
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

    def _decode_via_scapy(self, kwp_pkt):
        """Extract service id, name, and params dict from a Scapy KWP packet."""
        service_hex = kwp_pkt.fields.get("service", 0)
        service_name = kwp_pkt.sprintf("%KWP.service%")

        if service_name.startswith("0x") or service_name.isdigit():
            req_name = None
            if isinstance(service_hex, int) and service_hex > 0x40:
                req_id = service_hex - 0x40
                _, req_name = self.defs.lookup(req_id)
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
# TraceAnalyzer — pure pipeline orchestrator
# ---------------------------------------------------------------------------

class TraceAnalyzer:
    """Orchestrates the CAN → ISOTP → KWP protocol pipeline over a file or live bus."""

    def __init__(
        self,
        trace_file=None,
        interface=None,
        channel=None,
        bitrate=None,
        addressing="standard",
        defs_file=None,
        filter_file=None,
        physical_ids=None,
        functional_ids=None,
        can_hook=None,
        isotp_hook=None,
        kwp_hook=None,
    ):
        self.trace_file = trace_file
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate

        self.filter = FilterEngine(filter_file)
        self.defs = DefsEngine(defs_file)
        self.reassembler = ISOTPReassembler(addressing, physical_ids, functional_ids)
        self.kwp_decoder = KWPDecoder(self.defs)

        self.can_hook = can_hook
        self.isotp_hook = isotp_hook
        self.kwp_hook = kwp_hook

        self.can_count = 0
        self.isotp_count = 0
        self.kwp_count = 0

    def analyze(self):
        """Open the data source and run the full protocol pipeline until exhausted."""
        reader = self._open_source()
        self.reassembler.reset()
        self.can_count = 0
        self.isotp_count = 0
        self.kwp_count = 0

        try:
            for raw_msg in reader:
                if raw_msg.is_error_frame or raw_msg.is_remote_frame:
                    continue

                # ── CAN layer ────────────────────────────────────────────────────
                self.can_count += 1
                direction = "Rx" if raw_msg.is_rx else "Tx"
                can_frame = CANFrame(
                    raw_msg.arbitration_id, raw_msg.data, raw_msg.timestamp, direction
                )

                if self.filter.should_drop(can_frame):
                    continue

                if self.can_hook:
                    self.can_hook(can_frame)

                # ── ISOTP layer ──────────────────────────────────────────────────
                if not self.reassembler.is_isotp_id(can_frame.arb_id):
                    continue

                isotp_msg = self.reassembler.process(can_frame)
                if not isotp_msg:
                    continue

                self.isotp_count += 1
                if self.filter.should_drop(isotp_msg):
                    continue

                if self.isotp_hook:
                    self.isotp_hook(isotp_msg)

                # ── KWP layer ────────────────────────────────────────────────────
                kwp_msg = self.kwp_decoder.process(isotp_msg)
                if not kwp_msg:
                    continue

                if self.filter.should_drop(kwp_msg):
                    continue

                self.kwp_count += 1
                if self.kwp_hook:
                    self.kwp_hook(kwp_msg)

        except KeyboardInterrupt:
            print("\nCapture interrupted by user.", file=sys.stderr)

        print(
            f"Processed {self.can_count} CAN frames,"
            f" yielding {self.isotp_count} ISOTPs and {self.kwp_count} KWPs.",
            file=sys.stderr,
        )

    def _open_source(self):
        """Open and return a CAN message iterator (live bus or ASC file reader)."""
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
        print(
            f"Reading {self.trace_file} in real-time streaming mode...",
            file=sys.stderr,
        )
        return can.ASCReader(self.trace_file)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def setup_parser():
    """Build and return the core argument parser."""
    parser = argparse.ArgumentParser(
        description="Python-based CAN Trace Analyzer using Scapy"
    )
    parser.add_argument(
        "trace_file", nargs="?",
        help="Path to the .asc trace file to analyze (if not using live interface).",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Live python-can interface (e.g., 'pcan', 'socketcan', 'vector').",
    )
    parser.add_argument(
        "-c", "--channel",
        help="Live python-can channel (e.g., 'vcan0', 'PCAN_USBBUS1'). Required if --interface is used.",
    )
    parser.add_argument(
        "-b", "--bitrate", type=int,
        help="Bitrate for live interfaces (e.g., 500000).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print verbose full-packet Scapy dissected output",
    )
    parser.add_argument(
        "-A", "--addressing", choices=["standard", "extended"], default="standard",
        help="Type of ISOTP addressing layer (default: standard)",
    )
    parser.add_argument(
        "-d", "--defs",
        help="Optional JSON file defining custom service layouts to override Scapy",
    )
    parser.add_argument(
        "--filter",
        help="Optional JSON filter engine configuration to dynamically route and drop payloads.",
    )
    parser.add_argument(
        "--physical-ids", nargs="+",
        help="Optional list of physical CAN Arbitration IDs (hex or decimal) to natively parse as ISO-TP.",
    )
    parser.add_argument(
        "--functional-ids", nargs="+",
        help="Optional list of functional CAN Arbitration IDs (hex or decimal) to natively parse as ISO-TP.",
    )
    parser.add_argument(
        "--hook",
        help="Optional Python file defining protocol hooks (e.g. on_kwp_message)",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Load plugin, parse arguments, construct analyzer, and run the pipeline."""
    arg_parser = setup_parser()
    known_args, _ = arg_parser.parse_known_args()

    can_hook = None
    isotp_hook = None
    kwp_hook = None
    plugin_init = None
    plugin_teardown = None

    if known_args.hook:
        hook_path = os.path.abspath(known_args.hook)
        try:
            spec = importlib.util.spec_from_file_location("plugin_hook", hook_path)
            hook_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hook_mod)

            if hasattr(hook_mod, "add_arguments"):
                hook_mod.add_arguments(arg_parser)

            can_hook = getattr(hook_mod, "on_can_message", None)
            isotp_hook = getattr(hook_mod, "on_isotp_message", None)
            kwp_hook = getattr(hook_mod, "on_kwp_message", None)
            plugin_init = getattr(hook_mod, "init", None)
            plugin_teardown = getattr(hook_mod, "teardown", None)

            print(f"Loaded plugin hooks from {known_args.hook}", file=sys.stderr)
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"Failed to load hook plugin {known_args.hook}: {e}", file=sys.stderr)

    args = arg_parser.parse_args()

    if args.interface and not args.channel:
        arg_parser.error("--channel is required when --interface is specified.")
    if not args.interface and not args.trace_file:
        arg_parser.error(
            "You must specify either a trace_file or a live --interface (with --channel)."
        )

    if plugin_init:
        plugin_init(args)

    try:
        analyzer = TraceAnalyzer(
            trace_file=args.trace_file,
            interface=args.interface,
            channel=args.channel,
            bitrate=args.bitrate,
            addressing=args.addressing,
            defs_file=args.defs,
            filter_file=args.filter,
            physical_ids=getattr(args, "physical_ids", None),
            functional_ids=getattr(args, "functional_ids", None),
            can_hook=can_hook,
            isotp_hook=isotp_hook,
            kwp_hook=kwp_hook,
        )
        analyzer.analyze()
    finally:
        if plugin_teardown:
            plugin_teardown()


if __name__ == "__main__":
    main()

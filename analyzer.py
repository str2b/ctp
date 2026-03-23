import argparse
import sys
import json
import can
from scapy.all import sniff, Raw
from scapy.layers.can import CAN
from scapy.contrib.automotive.kwp import KWP
from scapy.contrib.isotp import ISOTP, ISOTPSession


def setup_parser():
    parser = argparse.ArgumentParser(
        description="Python-based CAN Trace Analyzer using Scapy"
    )
    parser.add_argument(
        "trace_file",
        nargs="?",
        help="Path to the .asc trace file to analyze (if not using live interface)."
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
        "-b",
        "--bitrate",
        type=int,
        help="Bitrate for live interfaces (e.g., 500000).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print verbose full-packet Scapy dissected output",
    )
    parser.add_argument(
        "-A",
        "--addressing",
        choices=["standard", "extended"],
        default="standard",
        help="Type of ISOTP addressing layer (default: standard)",
    )
    parser.add_argument(
        "-d",
        "--defs",
        help="Optional JSON file defining custom service layouts to override Scapy",
    )
    parser.add_argument(
        "--filter",
        help="Optional JSON filter engine configuration to dynamically route and drop payloads.",
    )
    parser.add_argument(
        "--hook",
        help="Optional Python file defining protocol hooks (e.g. on_kwp_message)",
    )
    return parser


class TraceAnalyzer:
    def __init__(
        self,
        trace_file=None,
        interface=None,
        channel=None,
        bitrate=None,
        verbose=False,
        addressing="standard",
        defs_file=None,
        filter_file=None,
        can_hook=None,
        isotp_hook=None,
        kwp_hook=None,
    ):
        self.trace_file = trace_file
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate
        self.verbose = verbose
        self.addressing = addressing.lower()
        self.can_hook = can_hook
        self.isotp_hook = isotp_hook
        self.kwp_hook = kwp_hook
        self.id_to_target = {}
        self.id_to_dir = {}

        self.custom_defs = {}
        if defs_file:
            try:
                with open(defs_file, "r") as f:
                    self.custom_defs = json.load(f)
                print(f"Loaded custom definitions from {defs_file}", file=sys.stderr)
            except Exception as e:
                print(f"Failed to load defs file {defs_file}: {e}", file=sys.stderr)

        self.filter_mode = "whitelist"
        self.filter_rules = []
        if filter_file:
            try:
                with open(filter_file, "r", encoding="utf-8") as f:
                    filter_def = json.load(f)
                    self.filter_mode = filter_def.get("mode", "whitelist").lower()
                    self.filter_rules = filter_def.get("rules", [])
                print(
                    f"Loaded {len(self.filter_rules)} core filter rules in {self.filter_mode} mode.",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"Failed to load filter file {filter_file}: {e}", file=sys.stderr)
                sys.exit(1)

    def should_drop(self, layer, **kwargs):
        """Evaluates attributes against JSON filter layer definitions. Returns True if frame should be discarded."""
        if not self.filter_rules:
            return False

        layer_rules = [
            r for r in self.filter_rules if r.get("layer", "").lower() == layer
        ]
        if not layer_rules:
            # Per-layer evaluation: if layer has no configuration, it is unrestrained
            # and relies entirely on other layer rules to police it.
            return False

        rule_matched = False
        import re

        for rule in layer_rules:
            rule_matches = True
            for key, expected_val in rule.items():
                if key == "layer":
                    continue
                val = kwargs.get(key)
                if val is None:
                    rule_matches = False
                    break
                if key == "payload":
                    if not isinstance(val, (bytes, bytearray)):
                        rule_matches = False
                        break
                    if not re.search(
                        str(expected_val), val.hex().upper(), re.IGNORECASE
                    ):
                        rule_matches = False
                        break
                else:
                    str_val = str(val).upper()
                    if isinstance(val, int):
                        str_val = f"0x{val:0X}"
                    exp_val_str = str(expected_val).upper()
                    if str_val != exp_val_str and exp_val_str != str(val):
                        rule_matches = False
                        break
            if rule_matches:
                rule_matched = True
                break

        if self.filter_mode == "whitelist":
            return not rule_matched
        return rule_matched

    def process_isotp(self, timestamp, direction, arb_id, target_addr, payload):
        if len(payload) == 0:
            return

        if self.addressing == "extended":
            session_key = (arb_id, target_addr)
        else:
            session_key = arb_id

        pci = payload[0] >> 4

        if pci == 0:
            # Single Frame
            dl = payload[0] & 0x0F
            if 0 < dl <= len(payload) - 1:
                isotp_payload = payload[1 : 1 + dl]
                self.process_kwp(
                    timestamp, direction, session_key, bytes(isotp_payload)
                )

        elif pci == 1:
            # First Frame
            if len(payload) >= 2:
                dl = ((payload[0] & 0x0F) << 8) | payload[1]
                self.isotp_sessions[session_key] = {
                    "dl": dl,
                    "data": bytearray(payload[2:]),
                }

        elif pci == 2:
            # Consecutive Frame
            if session_key in self.isotp_sessions:
                self.isotp_sessions[session_key]["data"].extend(payload[1:])
                if (
                    len(self.isotp_sessions[session_key]["data"])
                    >= self.isotp_sessions[session_key]["dl"]
                ):
                    full_data = self.isotp_sessions[session_key]["data"][
                        : self.isotp_sessions[session_key]["dl"]
                    ]
                    del self.isotp_sessions[session_key]
                    self.process_kwp(
                        timestamp, direction, session_key, bytes(full_data)
                    )

    def process_kwp(self, timestamp, direction, session_key, payload_bytes):
        class DummyISOTPPacket:
            def __init__(self):
                self.rx_id = 0
                self.time = 0.0
                self.direction = "??"
                self.payload_bytes = b""

        isotp_pkt = DummyISOTPPacket()
        if self.addressing == "extended":
            isotp_pkt.rx_id = session_key[0]
            tgt_addr = session_key[1]
        else:
            isotp_pkt.rx_id = session_key
            tgt_addr = self.id_to_target.get(session_key, 0xFF)

        isotp_pkt.time = timestamp
        isotp_pkt.direction = direction
        isotp_pkt.payload_bytes = payload_bytes

        if self.should_drop("isotp", payload=payload_bytes):
            return

        self.isotp_count += 1
        if self.isotp_hook:
            self.isotp_hook(isotp_pkt)

        if len(payload_bytes) >= 1 and payload_bytes[0] in range(0x10, 0xFF):
            try:
                handled = False
                if self.custom_defs:
                    src = isotp_pkt.rx_id & 0xFF
                    service_id = payload_bytes[0]

                    if self.should_drop(
                        "kwp",
                        src=src,
                        tgt=tgt_addr,
                        service=f"0x{service_id:0X}",
                        payload=payload_bytes,
                    ):
                        return

                    basic_info = {
                        "src": src,
                        "tgt": tgt_addr,
                        "service_hex": service_id,
                        "service_name": "",
                        "params": {},
                    }

                    fast_info = self.parse_custom_payload(payload_bytes, basic_info)
                    if fast_info:
                        self.kwp_count += 1
                        if self.kwp_hook:
                            self.kwp_hook(Raw(payload_bytes), fast_info, isotp_pkt)
                        handled = True

                if not handled:
                    kwp_msg = KWP(payload_bytes)

                    self.kwp_count += 1
                    parsed_info = self.parse_kwp_message(kwp_msg, isotp_pkt)
                    if self.kwp_hook:
                        self.kwp_hook(kwp_msg, parsed_info, isotp_pkt)
            except Exception as e:
                print(f"Error parsing KWP packet at {timestamp}: {e}", file=sys.stderr)

    def parse_kwp_message(self, kwp_msg, isotp_pkt):
        """Extracts and formats KWP attributes into a dictionary for hooks to easily consume."""
        arb_id = getattr(isotp_pkt, "rx_id", 0)
        src = arb_id & 0xFF
        tgt = self.id_to_target.get(arb_id, 0xFF)

        service_name = kwp_msg.sprintf("%KWP.service%")
        service_hex = kwp_msg.fields.get("service", 0)

        # Scapy returns the hex string if it cannot resolve the KWP service enum
        if service_name.startswith("0x") or service_name.isdigit():
            req_name = None
            # Guard: subtraction only makes sense if service_hex > 0x40
            if isinstance(service_hex, int) and service_hex > 0x40:
                req_id = service_hex - 0x40
                # 1. Try custom_defs
                if self.custom_defs:
                    _, req_name = self._lookup_service_def(req_id)
                # 2. Try Scapy if custom_defs had no match
                if not req_name:
                    try:
                        req_scapy_name = KWP(bytes([req_id])).sprintf("%KWP.service%")
                        if not (
                            req_scapy_name.startswith("0x") or req_scapy_name.isdigit()
                        ):
                            req_name = req_scapy_name
                    except Exception:
                        pass
            if req_name:
                service_name = f"{req_name}PositiveResponse"
            else:
                service_name = "<Unknown_Service>"

        params_dict = {}
        if kwp_msg.payload:
            for k, v in kwp_msg.payload.fields.items():
                if isinstance(v, int):
                    field_obj = kwp_msg.payload.get_field(k)
                    if field_obj:
                        repr_val = str(field_obj.i2repr(kwp_msg.payload, v))
                        if repr_val.startswith("'") and repr_val.endswith("'"):
                            repr_val = repr_val[1:-1]

                        if (
                            repr_val
                            and not repr_val.isdigit()
                            and not repr_val.lower().startswith("0x")
                        ):
                            params_dict[k] = {"value": v, "name": repr_val}
                        else:
                            params_dict[k] = v
                    else:
                        params_dict[k] = v
                else:
                    params_dict[k] = v

            # Always check for unparsed Raw trailing bytes deeper in the layer tree
            if kwp_msg.haslayer(Raw):
                raw_bytes = getattr(kwp_msg.getlayer(Raw), "load", b"")
                if raw_bytes:
                    if len(params_dict) == 0:
                        params_dict["raw_payload"] = raw_bytes
                    else:
                        params_dict["trailing_payload"] = raw_bytes

        return {
            "src": src,
            "tgt": tgt,
            "service_hex": service_hex,
            "service_name": service_name,
            "params": params_dict,
        }

    def _lookup_service_def(self, service_id):
        """Lookup a single service ID in the custom defs. Returns (service_def, name) or (None, None)."""
        services_dict = self.custom_defs.get("services", self.custom_defs)
        hex_key = f"0x{service_id:02X}"
        str_key = str(service_id)
        service_def = services_dict.get(hex_key) or services_dict.get(str_key)
        if service_def:
            return service_def, service_def.get("name", f"CustomService_{hex_key}")
        return None, None

    def parse_custom_payload(self, payload_bytes, basic_info):
        """Bypass Scapy and map payload exactly based on custom JSON definitions."""
        if not self.custom_defs or len(payload_bytes) < 1:
            return None

        service_id = payload_bytes[0]

        service_def, service_name = self._lookup_service_def(service_id)

        if not service_def:
            return None

        basic_info["service_name"] = service_name

        args_layout = service_def.get("args") or {}

        payload_len_str = str(len(payload_bytes))
        layout = args_layout.get(payload_len_str, args_layout.get("default", []))

        params_dict = {}
        offset = 1

        layout_queue = list(layout)

        while layout_queue:
            param = layout_queue.pop(0)

            # Standalone Mux Routing Object
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
                str_val_str = str(int_val)

                cases = param["mux"]
                matched_mux = (
                    cases.get(hex_val_str)
                    or cases.get(str_val_str)
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
                raw_val = payload_bytes[offset : offset + p_len]
                offset += p_len

            # If length is 1-8 bytes, parse as integer to allow enum lookup
            if 0 < p_len <= 8:
                int_val = int.from_bytes(raw_val, byteorder="big")
                hex_val_str = f"0x{int_val:02X}"
                str_val_str = str(int_val)

                # Check enum map for string resolution
                enum_map = param.get("enum", {})
                named_val = enum_map.get(hex_val_str) or enum_map.get(str_val_str)

                # Fallback to range resolution
                if not named_val:
                    for k, v in enum_map.items():
                        if isinstance(k, str) and "-" in k:
                            try:
                                low_str, high_str = k.split("-", 1)
                                if (
                                    int(low_str.strip(), 0)
                                    <= int_val
                                    <= int(high_str.strip(), 0)
                                ):
                                    named_val = v
                                    break
                            except Exception:
                                pass

                if named_val:
                    params_dict[p_name] = {"value": int_val, "name": named_val}
                else:
                    if p_len == 1:
                        params_dict[p_name] = int_val
                    else:
                        params_dict[p_name] = raw_val

            else:
                params_dict[p_name] = raw_val

        if offset < len(payload_bytes):
            params_dict["trailing_payload"] = payload_bytes[offset:]

        basic_info["params"] = params_dict
        return basic_info

    def analyze(self):
        try:
            if self.interface:
                print(f"Opening LIVE interface '{self.interface}' on channel '{self.channel}'...", file=sys.stderr)
                kwargs = {"interface": self.interface, "channel": self.channel}
                if self.bitrate:
                    kwargs["bitrate"] = self.bitrate
                reader = can.Bus(**kwargs)
            else:
                if not self.trace_file:
                    print("Error: You must specify either a trace_file or a live --interface (with --channel).", file=sys.stderr)
                    sys.exit(1)
                print(f"Reading {self.trace_file} in real-time streaming mode...", file=sys.stderr)
                reader = can.ASCReader(self.trace_file)
        except Exception as e:
            print(f"Error opening data source: {e}", file=sys.stderr)
            sys.exit(1)

        self.isotp_sessions = {}
        self.can_count = 0
        self.isotp_count = 0
        self.kwp_count = 0

        for msg in reader:
            if msg.is_error_frame or msg.is_remote_frame:
                continue

            self.can_count += 1
            arb_id = msg.arbitration_id
            direction = "Rx" if msg.is_rx else "Tx"
            self.id_to_dir[arb_id] = direction

            if self.addressing == "extended":
                if len(msg.data) >= 2:
                    target_addr = msg.data[0]
                    self.id_to_target[arb_id] = target_addr

                    if self.should_drop("can", id=arb_id, payload=msg.data):
                        continue

                    if self.can_hook:
                        pkt = CAN(identifier=arb_id, data=msg.data[1:])
                        pkt.time = msg.timestamp
                        pkt.direction = direction
                        self.can_hook(pkt)

                    self.process_isotp(
                        msg.timestamp, direction, arb_id, target_addr, msg.data[1:]
                    )
            else:
                if self.should_drop("can", id=arb_id, payload=msg.data):
                    continue

                if self.can_hook:
                    pkt = CAN(identifier=arb_id, data=msg.data)
                    pkt.time = msg.timestamp
                    pkt.direction = direction
                    self.can_hook(pkt)

                self.process_isotp(
                    msg.timestamp,
                    direction,
                    arb_id,
                    self.id_to_target.get(arb_id, 0xFF),
                    msg.data,
                )

        print(
            f"Processed {self.can_count} CAN frames, yielding {self.isotp_count} ISOTPs and {self.kwp_count} KWPs.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    parser = setup_parser()
    known_args, _ = parser.parse_known_args()

    can_hook = None
    isotp_hook = None
    kwp_hook = None
    kwp_fast_parse = None
    plugin_init = None

    if known_args.hook:
        import importlib.util
        import os

        hook_path = os.path.abspath(known_args.hook)
        try:
            spec = importlib.util.spec_from_file_location("plugin_hook", hook_path)
            hook_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hook_mod)

            # Allow plugin to register its own arguments
            if hasattr(hook_mod, "add_arguments"):
                hook_mod.add_arguments(parser)

            can_hook = getattr(hook_mod, "on_can_message", None)
            isotp_hook = getattr(hook_mod, "on_isotp_message", None)
            kwp_hook = getattr(hook_mod, "on_kwp_message", None)
            plugin_init = getattr(hook_mod, "init", None)
            plugin_teardown = getattr(hook_mod, "teardown", None)

            print(f"Loaded plugin hooks from {known_args.hook}", file=sys.stderr)
        except Exception as e:
            print(f"Failed to load hook plugin {known_args.hook}: {e}", file=sys.stderr)

    # Second pass: fully parse all args including those added by plugin
    args = parser.parse_args()

    if args.interface and not args.channel:
        parser.error("--channel is required when --interface is specified.")
    if not args.interface and not args.trace_file:
        parser.error("You must specify either a trace_file or a live --interface (with --channel).")

    # Give the plugin a chance to read its args
    if plugin_init:
        plugin_init(args)

    try:
        analyzer = TraceAnalyzer(
            trace_file=args.trace_file,
            interface=args.interface,
            channel=args.channel,
            bitrate=args.bitrate,
            verbose=args.verbose,
            addressing=args.addressing,
            defs_file=args.defs,
            filter_file=args.filter,
            can_hook=can_hook,
            isotp_hook=isotp_hook,
            kwp_hook=kwp_hook,
        )
        analyzer.analyze()
    finally:
        if plugin_teardown:
            plugin_teardown()

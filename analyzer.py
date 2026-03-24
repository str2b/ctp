import argparse
import re
import sys
import json
import can
from scapy.all import Raw
from scapy.layers.can import CAN
from scapy.contrib.automotive.kwp import KWP

class ISOTPMessage:
    def __init__(self, rx_id, tgt_addr, time, direction, payload_bytes, can_frames=None, frame_type="data"):
        self.rx_id = rx_id
        self.tgt_addr = tgt_addr
        self.time = time
        self.direction = direction
        self.payload_bytes = payload_bytes
        self.can_frames = can_frames or []
        self.frame_type = frame_type  # "data" | "flow_control"

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
        "--physical-ids",
        nargs="+",
        help="Optional list of physical CAN Arbitration IDs (hex or decimal) to natively parse as ISO-TP.",
    )
    parser.add_argument(
        "--functional-ids",
        nargs="+",
        help="Optional list of functional CAN Arbitration IDs (hex or decimal) to natively parse as ISO-TP.",
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
        self.verbose = verbose
        self.addressing = addressing.lower()

        self.use_custom_ids = physical_ids is not None or functional_ids is not None
        self.diagnostic_ids = set()
        for ids_list in (physical_ids, functional_ids):
            if ids_list:
                for rxid in ids_list:
                    try:
                        self.diagnostic_ids.add(int(rxid, 16) if rxid.lower().startswith('0x') else int(rxid))
                    except Exception:
                        pass

        self.can_hook = can_hook
        self.isotp_hook = isotp_hook
        self.kwp_hook = kwp_hook
        self.id_to_target = {}
        self.id_to_dir = {}

        # Runtime counters and ISOTP reassembly state (reset per analyze() call)
        self.isotp_sessions = {}
        self.can_count = 0
        self.isotp_count = 0
        self.kwp_count = 0

        self.custom_defs = {}
        if defs_file:
            try:
                with open(defs_file, "r", encoding="utf-8") as f:
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

    def is_isotp_id(self, arb_id):
        if self.use_custom_ids:
            return arb_id in self.diagnostic_ids

        if 0x600 <= arb_id <= 0x6FF:
            return True
        if 0x7DF <= arb_id <= 0x7EF:
            return True
        if arb_id & 0x00FFFF00 in (0x00DA0000, 0x00DB0000):
            return True

        return False

    def process_isotp(self, timestamp, direction, arb_id, payload):
        if len(payload) == 0:
            return None

        if self.addressing == "extended":
            if len(payload) < 2:
                return None
            target_addr = payload[0]
            self.id_to_target[arb_id] = target_addr
            isotp_payload = payload[1:]
            session_key = (arb_id, target_addr)
            rx_id = session_key[0]
        else:
            target_addr = self.id_to_target.get(arb_id, 0xFF)
            isotp_payload = payload
            session_key = arb_id
            rx_id = session_key

        if len(isotp_payload) == 0:
            return None

        pci = isotp_payload[0] >> 4
        can_frame_entry = (timestamp, direction, arb_id, payload)

        if pci == 0:
            # Single Frame
            dl = isotp_payload[0] & 0x0F
            if 0 < dl <= len(isotp_payload) - 1:
                if dl > (7 if self.addressing == "standard" else 6):
                    return None

                isotp_payload_extracted = isotp_payload[1 : 1 + dl]

                # Validation for padding bytes.
                padding_bytes = isotp_payload[1 + dl :]
                if len(padding_bytes) > 0:
                    if len(set(padding_bytes)) > 1:
                        return None
                    if padding_bytes[0] not in (0x00, 0x55, 0xAA, 0xCC, 0xFF):
                        return None

                return ISOTPMessage(rx_id, target_addr, timestamp, direction, bytes(isotp_payload_extracted), [can_frame_entry])

        elif pci == 1:
            # First Frame
            if len(isotp_payload) >= 2:
                dl = ((isotp_payload[0] & 0x0F) << 8) | isotp_payload[1]
                if dl > (7 if self.addressing == "standard" else 6):
                    self.isotp_sessions[session_key] = {
                        "dl": dl,
                        "data": bytearray(isotp_payload[2:]),
                        "sn": 1,
                        "can_frames": [can_frame_entry]
                    }

        elif pci == 2:
            # Consecutive Frame
            if session_key in self.isotp_sessions:
                sn = isotp_payload[0] & 0x0F
                expected_sn = self.isotp_sessions[session_key]["sn"]

                if sn == expected_sn:
                    self.isotp_sessions[session_key]["data"].extend(isotp_payload[1:])
                    self.isotp_sessions[session_key]["sn"] = (sn + 1) & 0x0F
                    self.isotp_sessions[session_key]["can_frames"].append(can_frame_entry)

                    if len(self.isotp_sessions[session_key]["data"]) >= self.isotp_sessions[session_key]["dl"]:
                        full_data = self.isotp_sessions[session_key]["data"][: self.isotp_sessions[session_key]["dl"]]
                        frames = self.isotp_sessions[session_key]["can_frames"]
                        del self.isotp_sessions[session_key]
                        return ISOTPMessage(rx_id, target_addr, timestamp, direction, bytes(full_data), frames)
                else:
                    del self.isotp_sessions[session_key]

        elif pci == 3:
            # Flow Control — ISOTP protocol frame only, must NOT reach KWP
            fs = isotp_payload[0] & 0x0F
            if fs <= 2 and len(isotp_payload) >= 3:
                padding_bytes = isotp_payload[3:]
                if len(padding_bytes) > 1 and len(set(padding_bytes)) > 1:
                    return None
                return ISOTPMessage(rx_id, target_addr, timestamp, direction,
                                   bytes(isotp_payload[:3]), [can_frame_entry],
                                   frame_type="flow_control")

        return None

    def process_kwp(self, isotp_pkt):
        payload_bytes = isotp_pkt.payload_bytes

        if len(payload_bytes) >= 1 and payload_bytes[0] in range(0x10, 0xFF):
            try:
                src = isotp_pkt.rx_id & 0xFF
                tgt_addr = isotp_pkt.tgt_addr
                service_id = payload_bytes[0]

                if self.should_drop(
                    "kwp",
                    src=src,
                    tgt=tgt_addr,
                    service=f"0x{service_id:0X}",
                    payload=payload_bytes,
                ):
                    return

                handled = False
                if self.custom_defs:

                    basic_info = {
                        "src": src,
                        "tgt": tgt_addr,
                        "service_hex": service_id,
                        "service_name": "",
                        "params": {},
                    }

                    defs_info = self.parse_custom_payload(payload_bytes, basic_info)
                    if defs_info:
                        self.kwp_count += 1
                        if self.kwp_hook:
                            self.kwp_hook(Raw(payload_bytes), defs_info, isotp_pkt)
                        handled = True

                if not handled:
                    kwp_msg = KWP(payload_bytes)

                    self.kwp_count += 1
                    parsed_info = self.parse_kwp_message(kwp_msg, isotp_pkt)
                    if self.kwp_hook:
                        self.kwp_hook(kwp_msg, parsed_info, isotp_pkt)
            except Exception as e:
                print(f"Error parsing KWP packet 0x{payload_bytes[0]:02X} on 0x{isotp_pkt.rx_id:X}: {e}", file=sys.stderr)

    def parse_kwp_message(self, kwp_msg, isotp_pkt):
        """Extracts and formats KWP attributes into a dictionary for hooks to easily consume."""
        arb_id = getattr(isotp_pkt, "rx_id", 0)
        src = arb_id & 0xFF
        tgt = isotp_pkt.tgt_addr

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

            if self.should_drop("can", id=arb_id, payload=msg.data):
                continue

            if self.can_hook:
                pkt = CAN(identifier=arb_id, data=msg.data)
                pkt.time = msg.timestamp
                pkt.direction = direction
                self.can_hook(pkt)

            isotp_msg = None
            if self.is_isotp_id(arb_id):
                isotp_msg = self.process_isotp(
                    msg.timestamp, direction, arb_id, msg.data
                )

            if isotp_msg:
                self.isotp_count += 1
                if self.should_drop("isotp", payload=isotp_msg.payload_bytes):
                    continue
                if self.isotp_hook:
                    self.isotp_hook(isotp_msg)

                # Flow Control is an ISOTP transport layer mechanism — never forward to KWP
                if isotp_msg.frame_type == "data":
                    self.process_kwp(isotp_msg)

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
    plugin_init = None
    plugin_teardown = None

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

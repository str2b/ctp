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
    parser.add_argument("trace_file", help="Path to the .asc trace file to analyze")
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
        "-o", "--output", help="Optional output file to save logs to natively"
    )
    parser.add_argument(
        "--hook",
        help="Optional Python file defining protocol hooks (e.g. on_kwp_message)",
    )
    return parser

class TraceAnalyzer:
    def __init__(
        self,
        trace_file,
        verbose=False,
        addressing="standard",
        can_hook=None,
        isotp_hook=None,
        kwp_hook=None,
    ):
        self.trace_file = trace_file
        self.verbose = verbose
        self.addressing = addressing.lower()
        self.can_hook = can_hook
        self.isotp_hook = isotp_hook
        self.kwp_hook = kwp_hook
        self.id_to_target = {}
        self.id_to_dir = {}


    def get_can_packets(self):
        """Reads ASC file using python-can and converts to Scapy CAN packets."""
        print(f"Reading {self.trace_file}...", file=sys.stderr)

        try:
            reader = can.ASCReader(self.trace_file)
        except Exception as e:
            print(f"Error opening ASC file: {e}", file=sys.stderr)
            sys.exit(1)

        can_packets = []
        for msg in reader:
            if not msg.is_error_frame and not msg.is_remote_frame:
                if self.addressing == "extended":
                    if len(msg.data) >= 2:  # Must have at least Target + PCI
                        target_addr = msg.data[0]
                        source_addr = msg.arbitration_id & 0xFF
                        self.id_to_target[msg.arbitration_id] = target_addr
                        self.id_to_dir[msg.arbitration_id] = "Rx" if msg.is_rx else "Tx"
                        # Strip extended address to construct standard CAN frame
                        pkt = CAN(identifier=msg.arbitration_id, data=msg.data[1:])
                        pkt.time = msg.timestamp
                        pkt.direction = "Rx" if msg.is_rx else "Tx"
                        can_packets.append(pkt)
                        if self.can_hook:
                            self.can_hook(pkt)
                else:
                    # Generic standard CAN frame
                    self.id_to_dir[msg.arbitration_id] = "Rx" if msg.is_rx else "Tx"
                    pkt = CAN(identifier=msg.arbitration_id, data=msg.data)
                    pkt.time = msg.timestamp
                    pkt.direction = "Rx" if msg.is_rx else "Tx"
                    can_packets.append(pkt)
                    if self.can_hook:
                        self.can_hook(pkt)

        print(f"Loaded {len(can_packets)} standard CAN frames.", file=sys.stderr)
        return can_packets

    def parse_kwp_message(self, kwp_msg, isotp_pkt):
        """Extracts and formats KWP attributes into a dictionary for hooks to easily consume."""
        arb_id = getattr(isotp_pkt, "rx_id", 0)
        src = arb_id & 0xFF
        tgt = self.id_to_target.get(arb_id, 0xFF)

        service_name = kwp_msg.sprintf("%KWP.service%")
        service_hex = kwp_msg.fields.get("service", 0)

        # Scapy returns the hex string if it cannot resolve the KWP service enum
        if service_name.startswith("0x") or service_name.isdigit():
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


    def analyze(self):
        # 1. Parse raw CAN messages
        self.loaded_cans = self.get_can_packets()

        try:
            from scapy.contrib.automotive.kwp import KWP
        except ImportError:
            print(
                "ERROR: Could not import scapy automotive kwp modules.", file=sys.stderr
            )
            sys.exit(1)

        print("Reassembling ISOTP internally...", file=sys.stderr)

        isotp_sessions = {}
        isotp_results = []

        for p in self.loaded_cans:
            if len(p.data) < 1:
                continue

            arb_id = p.identifier
            # In get_can_packets, the target address was already stripped from p.data!
            # So p.data is now a standard ISOTP CAN payload (first byte is PCI).
            # But we can recover the target address from self.id_to_target.
            tgt = self.id_to_target.get(arb_id, 0xFF)

            if self.addressing == "extended":
                session_key = (arb_id, tgt)
            else:
                session_key = arb_id

            payload = p.data[:]

            if len(payload) == 0:
                continue

            pci = payload[0] >> 4

            if pci == 0:
                # Single Frame
                dl = payload[0] & 0x0F
                if dl > 0 and dl <= len(payload) - 1:
                    isotp_payload = payload[1 : 1 + dl]
                    isotp_results.append((p, isotp_payload, session_key))
            elif pci == 1:
                # First Frame
                if len(payload) >= 2:
                    dl = ((payload[0] & 0x0F) << 8) | payload[1]
                    isotp_sessions[session_key] = {
                        "dl": dl,
                        "data": bytearray(payload[2:]),
                    }
            elif pci == 2:
                # Consecutive Frame
                if session_key in isotp_sessions:
                    isotp_sessions[session_key]["data"].extend(payload[1:])
                    if (
                        len(isotp_sessions[session_key]["data"])
                        >= isotp_sessions[session_key]["dl"]
                    ):
                        # Finished reassembly
                        full_data = isotp_sessions[session_key]["data"][
                            : isotp_sessions[session_key]["dl"]
                        ]
                        isotp_results.append((p, bytes(full_data), session_key))
                        del isotp_sessions[session_key]

        print(f"Extracted {len(isotp_results)} ISOTP payloads.", file=sys.stderr)

        kwp_msg_count = 0
        for final_cf_pkt, payload_bytes, session_key in isotp_results:

            class DummyISOTPPacket:
                def __init__(self):
                    self.rx_id = 0
                    self.time = 0.0
                    self.direction = "??"
                    self.payload_bytes = b""

            isotp_pkt = DummyISOTPPacket()
            if self.addressing == "extended":
                isotp_pkt.rx_id = session_key[0]
            else:
                isotp_pkt.rx_id = session_key

            isotp_pkt.time = final_cf_pkt.time if hasattr(final_cf_pkt, "time") else 0.0
            isotp_pkt.direction = getattr(final_cf_pkt, "direction", "??")
            isotp_pkt.payload_bytes = payload_bytes

            if self.isotp_hook:
                self.isotp_hook(isotp_pkt)

            if len(payload_bytes) >= 1 and payload_bytes[0] in range(0x10, 0xFF):
                try:
                    kwp_msg = KWP(payload_bytes)
                    _ = getattr(kwp_msg, "service", None)

                    if kwp_msg:
                        kwp_msg_count += 1
                        parsed_info = self.parse_kwp_message(kwp_msg, isotp_pkt)
                        if self.kwp_hook:
                            self.kwp_hook(kwp_msg, parsed_info, isotp_pkt)
                except Exception as e:
                    pass

        print(f"Found {kwp_msg_count} KWP2000 messages.", file=sys.stderr)


if __name__ == "__main__":
    parser = setup_parser()
    known_args, _ = parser.parse_known_args()

    out_file = None
    if known_args.output:
        out_file = open(known_args.output, "w", encoding="utf-8")
        sys.stdout = out_file

    can_hook = None
    isotp_hook = None
    kwp_hook = None
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
            
            print(f"Loaded plugin hooks from {known_args.hook}", file=sys.stderr)
        except Exception as e:
            print(f"Failed to load hook plugin {known_args.hook}: {e}", file=sys.stderr)

    # Second pass: fully parse all args including those added by plugin
    args = parser.parse_args()

    # Give the plugin a chance to read its args
    if plugin_init:
        plugin_init(args)

    try:
        analyzer = TraceAnalyzer(
            args.trace_file,
            verbose=args.verbose,
            addressing=args.addressing,
            can_hook=can_hook,
            isotp_hook=isotp_hook,
            kwp_hook=kwp_hook,
        )
        analyzer.analyze()
    finally:
        if out_file:
            sys.stdout = sys.__stdout__
            out_file.close()

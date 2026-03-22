"""
KWP2000 Logger Hook Plugin
Implements specific enum resolution and pretty-printing logic for Generic traces.
Now cleanly implements its own argument parsing and custom payload definitions!
"""

import sys
import json
from scapy.all import Raw

try:
    from scapy.contrib.automotive.bmw.definitions import (
        Generic_specific_enum,
        Generic_memoryTypeIdentifiers,
    )
except ImportError:
    Generic_specific_enum = {}
    Generic_memoryTypeIdentifiers = {}

id_to_dir = {}

# Global configurations
print_layers = ["kwp"]


def add_arguments(parser):
    """Called by the core analyzer to let the plugin register its own arguments."""
    parser.add_argument(
        "-p",
        "--print",
        nargs="+",
        choices=["raw", "isotp", "kwp"],
        default=["isotp"],
        help="[Plugin] Which layers to print output for (default: isotp)",
    )


def init(args):
    """Called by the core analyzer after arguments are parsed."""
    global print_layers

    if hasattr(args, "print") and args.print:
        print_layers = args.print


def on_can_message(can_pkt):
    """Optional hook for raw CAN packets."""
    if "raw" not in print_layers:
        return

    dir_flag = getattr(can_pkt, "direction", None)
    if dir_flag is None or dir_flag == "??":
        dir_flag = "??"
    ts = can_pkt.time if hasattr(can_pkt, "time") else 0.0
    print(
        f"[{ts:15.6f}] {dir_flag:2} | CAN ID 0x{can_pkt.identifier:03X} | len={len(can_pkt.data)} | {can_pkt.data.hex()}"
    )


def on_isotp_message(isotp_pkt):
    """Optional hook for ISOTP payloads."""
    if "isotp" not in print_layers:
        return

    dir_flag = getattr(isotp_pkt, "direction", None)
    if dir_flag is None or dir_flag == "??":
        dir_flag = "??"
    ts = isotp_pkt.time if hasattr(isotp_pkt, "time") else 0.0
    length = len(isotp_pkt.payload_bytes)
    payload_hex = isotp_pkt.payload_bytes.hex()
    if len(payload_hex) > 64:
        payload_hex = payload_hex[:64] + f"...(+{(len(payload_hex)-64)//2} bytes)"
    print(f"[{ts:15.6f}] {dir_flag:2} | ISOTP Length: {length:4} bytes | {payload_hex}")


def format_params(params_dict):
    """Format dictionary parameter items inline, applying Generic enums."""
    formatted_params = []
    for k, v in params_dict.items():
        if (
            k in ("localIdentifier", "recordLocalIdentifier")
            and isinstance(v, int)
            and v in Generic_specific_enum
        ):
            formatted_params.append(f"{k}=0x{v:02X} ({Generic_specific_enum[v]})")
        elif (
            k == "memoryType"
            and isinstance(v, int)
            and v in Generic_memoryTypeIdentifiers
        ):
            formatted_params.append(
                f"{k}=0x{v:02X} ({Generic_memoryTypeIdentifiers[v]})"
            )
        elif isinstance(v, dict) and "name" in v and "value" in v:
            val = v["value"]
            formatted_params.append(
                f"{k}=0x{val:02X} ({v['name']})"
                if isinstance(val, int)
                else f"{k}={v['value']} ({v['name']})"
            )
        elif isinstance(v, (bytes, bytearray)):
            formatted_params.append(f"{k}=" + " ".join([f"0x{b:02X}" for b in v]))
        elif isinstance(v, int):
            formatted_params.append(f"{k}=0x{v:X}")
        else:
            formatted_params.append(f"{k}={v}")

    return ", ".join(formatted_params)


def on_kwp_message(kwp_msg, parsed_info, isotp_pkt):
    """Main trace logger hook."""
    if "kwp" not in print_layers:
        return

    raw_payload = isotp_pkt.payload_bytes
    timestamp = isotp_pkt.time if hasattr(isotp_pkt, "time") else 0.0

    params_str = format_params(parsed_info["params"])

    print(
        f"[{timestamp:15.6f}] [0x{parsed_info['src']:02X}->0x{parsed_info['tgt']:02X} | L:0x{len(raw_payload):04X}] [0x{parsed_info['service_hex']:02X} ({parsed_info['service_name'][:35]:<35}){' | ' + params_str if params_str else ''}]"
    )

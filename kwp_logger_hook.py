"""
KWP2000 Logger Hook Plugin
Implements specific enum resolution and pretty-printing logic for Generic traces.
Now cleanly implements its own argument parsing and custom payload definitions!
"""

import sys

try:
    from scapy.contrib.automotive.bmw.definitions import (
        Generic_specific_enum,
        Generic_memoryTypeIdentifiers,
    )
except ImportError:
    Generic_specific_enum = {}
    Generic_memoryTypeIdentifiers = {}

id_to_dir = {}

# Module-level state (encapsulated in dict to avoid global statements)
_state = {
    "print_layers": ["kwp"],
    "out_file": None,
}


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
    parser.add_argument(
        "-o", "--output", help="[Plugin] Optional file to redirect stdout to natively."
    )


def init(args):
    """Called by the core analyzer after arguments are parsed."""
    if hasattr(args, "print") and args.print:
        _state["print_layers"] = args.print

    if hasattr(args, "output") and args.output:
        _state["out_file"] = open(args.output, "w", encoding="utf-8")  # pylint: disable=consider-using-with
        sys.stdout = _state["out_file"]


def teardown():
    """Called by the core analyzer upon completion."""
    if _state["out_file"]:
        sys.stdout = sys.__stdout__
        _state["out_file"].close()
        _state["out_file"] = None


def on_can_message(can_frame):
    """Optional hook for raw CAN packets."""
    if "raw" not in _state["print_layers"]:
        return

    print(
        f"[{can_frame.timestamp:15.6f}] {can_frame.direction:2}"
        f" | CAN ID 0x{can_frame.arb_id:03X}"
        f" | len={len(can_frame.data)} | {can_frame.data.hex()}"
    )


def on_isotp_message(isotp_pkt):
    """Optional hook for ISOTP payloads."""
    if "isotp" not in _state["print_layers"]:
        return

    dir_flag = getattr(isotp_pkt, "direction", None) or "??"
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


def on_kwp_message(kwp_msg):
    """Main trace logger hook."""
    if "kwp" not in _state["print_layers"]:
        return

    data = kwp_msg.data
    params_str = format_params(kwp_msg.params)
    service_label = f"0x{kwp_msg.service_hex:02X} ({kwp_msg.service_name[:35]:<35})"
    trailer = f" | {params_str}" if params_str else ""

    print(
        f"[{kwp_msg.time:15.6f}]"
        f" [0x{kwp_msg.src:02X}->0x{kwp_msg.tgt:02X}"
        f" | L:0x{len(data):04X}]"
        f" [{service_label}{trailer}]"
    )

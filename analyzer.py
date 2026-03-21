import argparse
import sys
import json
import can
from scapy.all import sniff, Raw
from scapy.layers.can import CAN
from scapy.contrib.automotive.kwp import KWP
from scapy.contrib.isotp import ISOTP, ISOTPSession

try:
    from scapy.contrib.automotive.bmw.definitions import (
        Generic_specific_enum,
        Generic_memoryTypeIdentifiers,
    )
except ImportError:
    Generic_specific_enum = {}
    Generic_memoryTypeIdentifiers = {}


def parse_args():
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
        "-t",
        "--type",
        choices=["generic", "bmw"],
        default="generic",
        help="Type of communication addressing (default: generic)",
    )
    parser.add_argument(
        "-p",
        "--print",
        nargs="+",
        choices=["raw", "isotp", "kwp"],
        default=["kwp"],
        help="Which layers to print output for (default: kwp)",
    )
    parser.add_argument(
        "-o", "--output", help="Optional output file to save logs to natively"
    )
    parser.add_argument(
        "-d", "--defs", help="Optional JSON file defining custom service layouts to override Scapy"
    )
    return parser.parse_args()


class TraceAnalyzer:
    def __init__(
        self,
        trace_file,
        verbose=False,
        comm_type="generic",
        print_layers=None,
        defs_file=None,
        can_hook=None,
        isotp_hook=None,
        kwp_hook=None,
    ):
        self.trace_file = trace_file
        self.verbose = verbose
        self.comm_type = comm_type.lower()
        self.print_layers = print_layers if print_layers else ["kwp"]
        self.can_hook = can_hook if can_hook else self.default_can_logger
        self.isotp_hook = isotp_hook if isotp_hook else self.default_isotp_logger
        self.kwp_hook = kwp_hook if kwp_hook else self.default_kwp_logger
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
                if self.comm_type == "bmw":
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
                else:
                    # Generic standard CAN frame
                    self.id_to_dir[msg.arbitration_id] = "Rx" if msg.is_rx else "Tx"
                    pkt = CAN(identifier=msg.arbitration_id, data=msg.data)
                    pkt.time = msg.timestamp
                    pkt.direction = "Rx" if msg.is_rx else "Tx"
                    can_packets.append(pkt)
                    if "raw" in self.print_layers:
                        self.can_hook(pkt)

        print(f"Loaded {len(can_packets)} standard CAN frames.", file=sys.stderr)
        return can_packets

    def default_can_logger(self, can_pkt):
        """Default hook for raw CAN packets."""
        dir_flag = getattr(can_pkt, "direction", None)
        if dir_flag is None or dir_flag == "??":
            dir_flag = "??"
        ts = can_pkt.time if hasattr(can_pkt, "time") else 0.0
        print(
            f"[{ts:15.6f}] {dir_flag:2} | CAN ID 0x{can_pkt.identifier:03X} | len={len(can_pkt.data)} | {can_pkt.data.hex()}"
        )

    def default_isotp_logger(self, isotp_pkt):
        """Default hook for reassembled ISOTP fragments."""
        dir_flag = getattr(isotp_pkt, "direction", None)
        if dir_flag is None or dir_flag == "??":
            dir_flag = self.id_to_dir.get(getattr(isotp_pkt, "rx_id", 0), "??")
        ts = isotp_pkt.time if hasattr(isotp_pkt, "time") else 0.0
        length = len(isotp_pkt.payload_bytes)
        payload_hex = isotp_pkt.payload_bytes.hex()
        # Truncate ISOTP print if it's too long
        if len(payload_hex) > 64:
            payload_hex = payload_hex[:64] + f"...(+{(len(payload_hex)-64)//2} bytes)"
        print(
            f"[{ts:15.6f}] {dir_flag:2} | ISOTP Length: {length:4} bytes | {payload_hex}"
        )

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
                if (
                    self.comm_type == "bmw"
                    and k in ("localIdentifier", "recordLocalIdentifier")
                    and v in Generic_specific_enum
                ):
                    params_dict[k] = {"value": v, "name": Generic_specific_enum[v]}
                elif (
                    self.comm_type == "bmw"
                    and k == "memoryType"
                    and v in Generic_memoryTypeIdentifiers
                ):
                    params_dict[k] = {"value": v, "name": Generic_memoryTypeIdentifiers[v]}
                elif isinstance(v, int):
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

    def parse_custom_payload(self, payload_bytes, isotp_pkt):
        """Bypass Scapy and map payload exactly based on custom JSON definitions."""
        if len(payload_bytes) < 1:
            return None
            
        service_id = payload_bytes[0]
        hex_key = f"0x{service_id:02X}"
        str_key = str(service_id)
        
        services_dict = self.custom_defs.get("services", self.custom_defs)
        
        service_def = services_dict.get(hex_key) or services_dict.get(str_key)
            
        if not service_def:
            return None
            
        service_name = service_def.get("name", f"CustomService_{hex_key}")
        
        payload_len_str = str(len(payload_bytes))
        
        if "cases" in service_def:
            if payload_len_str in service_def["cases"]:
                layout = service_def["cases"][payload_len_str]
            elif "default" in service_def["cases"]:
                layout = service_def["cases"]["default"]
            else:
                layout = []
        else:
            layout = service_def.get("args", [])
        
        arb_id = getattr(isotp_pkt, "rx_id", 0)
        src = arb_id & 0xFF
        tgt = self.id_to_target.get(arb_id, 0xFF)
        
        params_dict = {}
        offset = 1  
        
        for param in layout:
            p_name = param.get("name", "unknown")
            p_len = param.get("length", 1)
            
            if offset >= len(payload_bytes):
                break
                
            if p_len == -1:
                raw_val = payload_bytes[offset:]
                offset = len(payload_bytes)
            else:
                raw_val = payload_bytes[offset:offset+p_len]
                offset += p_len
            
            # If length is 1-8 bytes, parse as integer to allow enum lookup
            if 0 < p_len <= 8:
                int_val = int.from_bytes(raw_val, byteorder='big')
                hex_val_str = f"0x{int_val:02X}"
                str_val_str = str(int_val)
                
                # Check enum map for string resolution
                enum_map = param.get("enum", {})
                named_val = enum_map.get(hex_val_str) or enum_map.get(str_val_str)
                
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
            
        return {
            "src": src,
            "tgt": tgt,
            "service_hex": service_id,
            "service_name": service_name,
            "params": params_dict,
        }

    def default_kwp_logger(self, kwp_msg, parsed_info, isotp_pkt):
        """Default hook called for each discovered KWP2000 message, printing maximum details."""
        timestamp = isotp_pkt.time if hasattr(isotp_pkt, "time") else 0.0

        # Recover exact original direction
        dir_flag = getattr(isotp_pkt, "direction", None)
        if dir_flag is None or dir_flag == "??":
            dir_flag = self.id_to_dir.get(getattr(isotp_pkt, "rx_id", 0), "??")

        if not self.verbose:
            # Concise single-line output
            formatted_params = []
            for k, v in parsed_info["params"].items():
                if isinstance(v, dict) and "name" in v and "value" in v:
                    formatted_params.append(f"{k}=0x{v['value']:02X} {v['name']}")
                elif isinstance(v, (bytes, bytearray)):
                    formatted_params.append(
                        f"{k}=" + " ".join([f"0x{b:02X}" for b in v])
                    )
                elif isinstance(v, int):
                    formatted_params.append(f"{k}=0x{v:X}")
                else:
                    formatted_params.append(f"{k}={v}")

            params_str = ", ".join(formatted_params)
            print(
                f"[{timestamp:10.4f}] [0x{parsed_info['src']:02X}->0x{parsed_info['tgt']:02X} | L:0x{len(isotp_pkt.payload_bytes):04X}] [0x{parsed_info['service_hex']:02X} {parsed_info['service_name'][:35]:<35} | {params_str}]"
            )
        else:
            # Verbose multi-line output
            arb_id = getattr(isotp_pkt, "rx_id", 0)
            print(f"\n{'='*80}")
            print(f"[{timestamp:.6f}] {dir_flag} | KWP2000 MESSAGE")
            print(
                f"Address: Source 0x{parsed_info['src']:02X} -> Target 0x{parsed_info['tgt']:02X} (CAN ID: 0x{arb_id:X})"
            )
            print(
                f"Service: {parsed_info['service_name']} (0x{parsed_info['service_hex']:02X})"
            )

            # Print full Scapy dissected packet details
            print("-" * 40)
            kwp_msg.show()

            # Enrich with KWP-specific knowledge
            if self.comm_type == "bmw":
                if hasattr(kwp_msg, "localIdentifier"):
                    lid = kwp_msg.localIdentifier
                    if lid in Generic_specific_enum:
                        print(
                            f"[*] Generic LocalIdentifier 0x{lid:02X}: {Generic_specific_enum[lid]}"
                        )

                if hasattr(kwp_msg, "recordLocalIdentifier"):
                    lid = kwp_msg.recordLocalIdentifier
                    if lid in Generic_specific_enum:
                        print(
                            f"[*] Generic RecordLocalIdentifier 0x{lid:02X}: {Generic_specific_enum[lid]}"
                        )

                if hasattr(kwp_msg, "memoryAddress"):
                    if hasattr(kwp_msg, "memoryType"):
                        mtype = kwp_msg.memoryType
                        if mtype in Generic_memoryTypeIdentifiers:
                            print(
                                f"[*] Generic MemoryType 0x{mtype:02X}: {Generic_memoryTypeIdentifiers[mtype]}"
                            )

            if kwp_msg.payload:
                print(f"Raw Underlayer: {bytes(kwp_msg.payload).hex()}")
            print(f"{'='*80}\n")

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

            if self.comm_type == "bmw":
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
            if self.comm_type == "bmw":
                isotp_pkt.rx_id = session_key[0]
            else:
                isotp_pkt.rx_id = session_key

            isotp_pkt.time = final_cf_pkt.time if hasattr(final_cf_pkt, "time") else 0.0
            isotp_pkt.direction = getattr(final_cf_pkt, "direction", "??")
            isotp_pkt.payload_bytes = payload_bytes

            if "isotp" in self.print_layers:
                self.isotp_hook(isotp_pkt)

            if "kwp" in self.print_layers:
                if len(payload_bytes) >= 1 and payload_bytes[0] in range(0x10, 0xFF):
                    try:
                        parsed_info = None
                        kwp_msg = None
                        
                        if self.custom_defs:
                            parsed_info = self.parse_custom_payload(payload_bytes, isotp_pkt)
                            
                        if parsed_info:
                            # Successfully bypassed scapy! We pass Raw wrapper to hook in case they want bytes
                            kwp_msg_count += 1
                            kwp_msg = Raw(payload_bytes)
                            self.kwp_hook(kwp_msg, parsed_info, isotp_pkt)
                        else:
                            # Fallback to Scapy logic
                            kwp_msg = KWP(payload_bytes)
                            _ = getattr(kwp_msg, "service", None)

                            if kwp_msg:
                                kwp_msg_count += 1
                                parsed_info = self.parse_kwp_message(kwp_msg, isotp_pkt)
                                self.kwp_hook(kwp_msg, parsed_info, isotp_pkt)
                    except Exception as e:
                        pass

        print(f"Found {kwp_msg_count} KWP2000 messages.", file=sys.stderr)


if __name__ == "__main__":
    args = parse_args()

    out_file = None
    if args.output:
        out_file = open(args.output, "w", encoding="utf-8")
        sys.stdout = out_file

    try:
        analyzer = TraceAnalyzer(
            args.trace_file,
            verbose=args.verbose,
            comm_type=args.type,
            print_layers=getattr(args, "print"),
            defs_file=args.defs,
        )
        analyzer.analyze()
    finally:
        if out_file:
            sys.stdout = sys.__stdout__
            out_file.close()

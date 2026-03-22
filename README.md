# CAN Trace KWP Parser

A Python tool for parsing CAN trace files (`.asc`), ISOTP payloads and KWP2000 messages. 

The core analyzer extracts protocols and delegates application-specific logic (like presentation and custom definitions) to plugins via a hook architecture.

## Core Features
- **CAN Parsing:** Reads `.asc` trace files using `python-can`.
- **ISOTP Reassembly:** Assembles fragmented ISOTP streams (supports standard and extended addressing).
- **KWP2000 Extraction:** Parses standard KWP2000 services using Scapy. Features a bypass mechanism for custom definitions.
- **Hook Architecture:** Extends functionality through user-defined python scripts.

## Usage

Example execution using the included hook:
```bash
python analyzer.py trace.asc -A extended --hook kwp_logger_hook.py -p kwp --defs custom_defs.json
```

### Core Arguments
- `trace_file`: Path to the `.asc` trace file.
- `-A`, `--addressing`: Type of ISOTP addressing layer (default: `standard`, choices: `standard`, `extended`).
- `-d`, `--defs`: Optional JSON file defining custom payload schemas.
- `--hook`: Path to a custom Python plugin script.
- `-o`, `--output`: Optional file to redirect `stdout`.
- `-v`, `--verbose`: Print Scapy output.

---

## Custom Definitions (JSON)
The core analyzer maps generic service bytes using an optional JSON definition file provided via `--defs`.

If a payload matches a definition, the analyzer parses it natively into a dictionary and bypasses Scapy, improving processing time on large traces.

**Example Definition:**
```json
{
  "services": {
    "0x99": {
      "name": "FictionalServiceKey",
      "args": {
        "default": [
          {
            "name": "fictionalId", 
            "length": 1,
            "enum": {"0x0A": "getStatus", "0x0B": "getSecurity"}
          },
          {
            "switch_on": "fictionalId",
            "mux": {
              "0x0A": [
                {"name": "fictionalSubStatus", "length": 1, "enum": {"0x01": "active", "0x00": "inactive"}}
              ],
              "0x0B": [
                {"name": "fictionalSecurity", "length": 4}
              ]
            }
          },
          {"name": "fictionalData", "length": -1}
        ]
      }
    }
  }
}
```
In this example:
1. If the KWP service ID is `0x99`, the core identifies it as `FictionalServiceKey`.
2. Based on payload length, the layout dictionary key is selected (in this case, `default`).
3. **Conditional Muxing:** After the parser evaluates `fictionalId`, the array pops a standalone router object (`mux`). To resolve its path, it queries the parser's memory using the `switch_on` parameter tag (`"fictionalId"`). If the memory state evaluates to `0x0A`, the `fictionalSubStatus` parameter is dynamically injected into the processing queue before reading `fictionalData`. If it evaluates to `0x0B`, `fictionalSecurity` is injected instead. This `mux` router naturally supports independent, cascading evaluations.

---

## Hook Architecture
Custom analyzer behavior is defined by passing a Python file to `--hook`. 

### Hook API
The core analyzer checks for the following optional functions in the plugin:

- `add_arguments(parser)`: Register command-line arguments specific to the plugin.
- `init(args)`: Called after arguments are parsed to initialize state.
- `on_can_message(can_pkt)`: Callback invoked for parsed CAN frames.
- `on_isotp_message(isotp_pkt)`: Callback invoked for reassembled ISOTP payloads.
- `on_kwp_message(kwp_msg, parsed_info, isotp_pkt)`: Callback invoked for KWP messages. `parsed_info` provides a dictionary containing generic fields (`src`, `tgt`, `service_hex`, `params`).

---

## Included Plugin: `kwp_logger_hook.py`
A default reference plugin tailored for generic KWP traces. It handles enum resolution string formatting and prints the output.

### Hook-specific Arguments
- `-p`, `--print`: Specifies which layers to output to `stdout` (`raw`, `isotp`, `kwp`).

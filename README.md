# CAN Trace Parser

A Python tool for parsing CAN traces (`.asc`), their ISOTP payloads and KWP2000 messages. 

The analyzer extracts protocols and delegates logic to plugins via a hook architecture.

Disclaimer: This started as a vibe-coding piece of script for some hobby analysis project, so don't expect production-ready code.

## Features
- **CAN Parsing:** Reads `.asc` trace files using `python-can`.
- **ISOTP Reassembly:** Assembles ISOTP streams (supports standard and extended addressing).
- **KWP2000 Extraction:** Parses KWP2000 services using Scapy or custom definitions.
- **UDS Support:** Not implemented yet, but planned.
- **Hook Architecture:** Extends functionality through python scripts.

---

## Arguments
- `trace_file`: Path to the `.asc` trace file (optional if using live interface).
- `-i`, `--interface`: python-can interface (e.g., `pcan`, `socketcan`, `vector`).
- `-c`, `--channel`: python-can channel (e.g., `vcan0`, `PCAN_USBBUS1`).
- `-b`, `--bitrate`: Bitrate for live interfaces (e.g., `500000`).
- `-A`, `--addressing`: ISOTP addressing (default: `standard`, choices: `standard`, `extended`).
- `-d`, `--defs <file.json>`: JSON defs file for KWP services.
- `--filter <file.json>`: JSON filter definition file.
- `--physical-ids <id1 id2 ...>`: Arbitration IDs for physical ISOTP.
- `--functional-ids <id1 id2 ...>`: Arbitration IDs for functional ISOTP.
- `--hook <file.py>`: Python plugin hook script.

---

## Architecture

The analyzer uses a layered pipeline:

1. **`FilterEngine`**: JSON-based rule matching at each layer.
2. **`DefsEngine`**: JSON-based KWP service and parameter decoding.
3. **`ISOTPReassembler`**: Stateful reassembly of multi-frame CAN messages.
4. **`KWPDecoder`**: Decoding using custom definitions or Scapy fallback.
5. **`TraceAnalyzer`**: Orchestrates the pipeline from source to hooks.

Data flows through the pipeline as objects: `CANFrame` → `ISOTPMessage` → `KWPMessage`.

---

## Custom Definitions (JSON)
The analyzer maps service bytes using a JSON definition file provided via `--defs`. Matches bypass Scapy to reduce processing time.

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
1. If the KWP service ID is `0x99`, it is identified as `FictionalServiceKey`.
2. Based on payload length, the layout key is selected.
3. **Conditional Muxing:** The `mux` object uses the `switch_on` tag to select the next parameters to parse.

### Enum Range Parsing
The `enum` dictionary supports integer matches (`"0x0A": "foo"`) and numerical ranges (`"0x1F0A-0x1F0F": "group"`). 

---

## Filtering Engine

The filter engine (`--filter`) drops ISOTP assemblies and KWP payloads during the parser loop.

Example `filter.json`:
```json
{
  "mode": "whitelist",
  "rules": [
    {
      "layer": "can",
      "id": "0x12F1",
      "payload": "^0210.*"
    },
    {
      "layer": "kwp",
      "src": "0xF1",
      "service": "0x31",
      "payload": "^3101"
    }
  ]
}
```

- **Modes**: `whitelist` drops payloads unless they match a rule. `blacklist` allows payloads unless they match a rule.
- **Payload Regex**: Evaluated against the hex string of the payload.
- **Constraints**: Parameters in a rule are AND'ed.

---

## Hook Architecture

### Hook API
Available optional functions in the plugin:

- `add_arguments(parser)`: Register CLI arguments.
- `init(args)`: Initialize state after argument parsing.
- `on_can_message(can_frame)`: Callback for `CANFrame` objects.
- `on_isotp_message(isotp_msg)`: Callback for `ISOTPMessage` objects.
- `on_kwp_message(kwp_msg)`: Callback for `KWPMessage` objects.
- `teardown()`: Callback invoked before termination.

---

## Plugin: `kwp_logger_hook.py`
A plugin for generic KWP traces.

### Arguments
- `-p`, `--print`: Layers to output (`raw`, `isotp`, `kwp`).
- `-o`, `--output`: Redirect output to a file.


## Examples

The `examples/` directory contains templates for the filtering engine and custom KWP service definitions. 

### 1. Filter Engine (`filter_demo.json`)
Demonstrates supported logic for the `--filter` argument:
- **Layer Targeting**: Rules for `can`, `isotp`, and `kwp` layers.
- **Whitelist/Blacklist Modes**: Controlling the default drop behavior.
- **Complex Constraints**: AND'ing multiple fields (e.g., `src` + `service` + `payload`).
- **Regex Logic**: Pattern matching for hex payloads (e.g., `^10.*` for Diagnostic Session).

### 2. Custom KWP Definitions (`kwp_defs_demo.json`)
Demonstrates core semantics for the `--defs` argument:
- **Static arg layouts**: Fixed-length parameters.
- **Trailing payloads**: Using `length: -1` to capture remaining bytes.
- **Enum Mapping**: Exact hex, integer, and range matches (`0x10-0x1F`).
- **Conditional Layouts (`mux`)**: Dynamic branching based on a previous parameter's value (`switch_on`).

### 3. Verification Trace (`smoke_test.asc`)
A synthetic CAN trace file used to verify the analyzer logic. It contains no real vehicle data.

Run the verification:
```bash
python ctp.py examples/smoke_test.asc --filter examples/filter_demo.json --defs examples/kwp_defs_demo.json --hook kwp_logger_hook.py -p isotp -p kwp
```

See [examples/](examples/) for configuration templates and a test trace.

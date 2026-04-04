# CAN Trace Parser

A Python tool for parsing CAN traces (`.asc`, `.blf`), their ISOTP payloads and KWP2000 messages.

The analyzer extracts protocols and fans out events to plugins via a plugin registry.

**Disclaimer:** This tool is for **educational and personal use only**. Use responsibly and only with authorization on systems you own or have explicit permission to analyze. 

This started as a vibe coding hobby project and is provided as-is.

## Features
- **Multi-Format Traces:** Reads `.asc` and `.blf` trace files.
- **ISOTP Reassembly:** Assembles ISOTP streams (supports standard and extended addressing).
- **KWP2000 Extraction:** Parses KWP2000 services using Scapy or custom definitions.
- **UDS Support:** Not implemented yet, but planned.
- **Plugin System:** Extend functionality by loading one or more Python plugin files.
---

## Arguments

**Source (mutually exclusive, required):**
- `-f`, `--trace-file <path>`: Path to trace file (`.asc`, `.blf`, etc.)
- `-i`, `--interface <name>`: Live python-can interface (e.g., `pcan`, `socketcan`, `vector`)

**Live Interface Options** (only with `--interface`):
- `-c`, `--channel <channel>`: CAN channel (e.g., `vcan0`, `PCAN_USBBUS1`) — **required** when using live interface
- `-b`, `--bitrate <rate>`: Bitrate for the interface (e.g., `500000`)

**Diagnostic & Decoding:**
- `-A`, `--addressing {standard,extended}`: ISOTP addressing mode (default: `standard`)
- `-d`, `--defs <file.json>`: Custom KWP service definitions
- `--filter <file.json>`: Payload filtering rules
- `--physical-ids <id1 id2 ...>`: Arbitration IDs for physical ISOTP
- `--functional-ids <id1 id2 ...>`: Arbitration IDs for functional ISOTP

**Extensibility:**
- `--plugin <file.py> [file.py ...]`: One or more Python plugin files

---

## Architecture

The analyzer uses a layered pipeline:

1. **`FilterEngine`**: JSON-based rule matching at each layer.
2. **`DefsEngine`**: JSON-based KWP service and parameter decoding.
3. **`ISOTPReassembler`**: Stateful reassembly of multi-frame CAN messages.
4. **`ProtocolRegistry`**: Tries each registered `ProtocolDecoder` in order; currently hosts `KWPDecoder` (Scapy + custom defs). Add a `UDSDecoder` here for UDS support.
5. **`PluginRegistry`**: Fans out decoded messages to all loaded plugins via `on_{layer}_message()`.
6. **`TraceAnalyzer`**: Orchestrates the pipeline from source to plugins.

Data flows through the pipeline as typed objects: `CANFrame` → `ISOTPMessage` → `KWPMessage` (or future `UDSMessage`).

---

## Custom Definitions (JSON)
The analyzer maps service bytes using a JSON definition file provided via `--defs`. Matches bypass Scapy to reduce processing time.

The `services` field is a dictionary mapping a Service ID (hex or decimal) to either a single definition object or a list of definition objects.
When defining multiple objects for the same service (e.g. ECU-specific variants or positive responses), the analyzer ranks candidates using the `src` and `tgt` attributes, matching them against the lower byte of the CAN IDs. A definition with a fully matching `src` or `tgt` is preferred over a generic one.

**Example Definition:**
```json
{
  "services": {
    "0x50": [
      {
        "name": "FictionalPositiveResponse_AA",
        "src": "0xAA",
        "args": {
          "default": [
            { "name": "status", "length": 1, "enum": {"0x01": "ok"} }
          ]
        }
      },
      {
        "name": "FictionalPositiveResponse_Generic",
        "args": {
          "default": [
            { "name": "status", "length": 1 }
          ]
        }
      }
    ],
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
1. Handlers can be targeted precisely (`0x50` uses `src: "0xAA"` to override the generic `0x50` fallback).
2. If the KWP service ID is `0x99`, it is identified as `FictionalServiceKey`.
3. Based on payload length, the layout key is selected.
4. **Conditional Muxing:** The `mux` object uses the `switch_on` tag to select the next parameters to parse.

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

## Plugin System

### Plugin API
Each plugin is a plain Python file. All functions are optional:

- `add_arguments(parser)`: Register CLI arguments with argparse.
- `init(args)`: Initialize state after argument parsing.
- `on_can_message(can_frame)`: Callback for `CANFrame` objects.
- `on_isotp_message(isotp_msg)`: Callback for `ISOTPMessage` objects.
- `on_kwp_message(kwp_msg)`: Callback for `KWPMessage` objects.
- `teardown()`: Callback invoked before termination.

Multiple plugins can be loaded simultaneously with `--plugin`. Each receives every event independently.

---

## Plugin: `trace_printer.py`
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
python ctp.py --trace-file examples/smoke_test.asc --filter examples/filter_demo.json --defs examples/kwp_defs_demo.json --plugin plugins/trace_printer.py -p can isotp kwp
```

See [examples/](examples/) for configuration templates and a test trace.

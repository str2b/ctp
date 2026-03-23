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
- `-d`, `--defs <file.json>`: Path to a JSON defs file extending KWP services.
- `--filter <file.json>`: Path to a JSON filter definition file.
- `--hook <file.py>`: Dynamically load a Python plugin hook script.
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

### Enum Range Parsing
The `enum` mapping dictionary supports exact integer matches (`"0x0A": "foo"`) as well as string-defined numerical ranges for grouping sets of values (`"0x1F0A-0x1F0F": "supplierSpecific"`). 
If an exact match is not found, the parser evaluates all hyphenated keys to see if the value falls inclusively within bounds.

---

## Core Filtering Engine

`analyzer.py` natively bundles a powerful filter routing engine, invoked via `--filter`. It drops excluded ISOTP assemblies and KWP payloads deep inside the parser loop, significantly reducing overhead vs dropping in plugins.

Create a JSON file dictating rules, e.g. `filter.json`:
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

Run it via:
```bash
python analyzer.py trace.asc --filter filter.json
```

**Filter Rules**:
- **Modes**: `whitelist` mode drops payloads unless they explicitly match at least one rule for their layer. Layer rules are evaluated sequentially up the parsed stack (e.g. CAN drops cascade implicitly, preventing ISOTP extraction entirely). `blacklist` allows everything through unless it hits a matching rule targeting its precise layer.
- **Payload Regex**: The string evaluated under `"payload"` is compiled natively as Python Regex (`re.search(pattern, re.IGNORECASE)`), targeting the raw payload's standard hex conversion string (e.g. `1022AABB`). 
  - Meaning `^...` strictly binds the prefix, and `.*` represents wildcard bytes.
- **AND Constraints**: Inside a rule dictionary block, parameters are structurally AND'ed (e.g. `src == 0xF1 AND service == 0x31 AND payload matching regex`). If you need `OR` variants, simply append standalone `{}` target dictionaries to the `"rules"` array.

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
- `teardown()`: Optional callback invoked locally right before the core engine gracefully terminates. Permits handling file teardown and internal clean up correctly.

---

## Included Plugin: `kwp_logger_hook.py`
A default reference plugin tailored for generic KWP traces. It handles enum resolution string formatting and prints the output.

### Hook-specific Arguments
- `-p`, `--print`: Specifies which layers to output to `stdout` (`raw`, `isotp`, `kwp`).
- `-o`, `--output`: Redirect standard generic logger output strictly to a file.

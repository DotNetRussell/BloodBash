
![BloodBash verbose output example](https://i.imgur.com/m5RVnJZ.png)

# BloodBash 🩸🐕

**BloodBash** is a powerful, standalone BloodHound JSON analyzer written in Python.  
It parses SharpHound (v6+) JSON files offline — no Neo4j or BloodHound GUI needed.

It builds a directed graph using `networkx`, correctly identifies object types, finds attack paths, detects vulnerabilities (especially ADCS ESC1–ESC8), and provides BloodHound-style queries with rich, colored output.

Perfect for red teamers, OSCP/CRTP prep, and fast AD reconnaissance when you only have raw SharpHound data.

![BloodBash verbose output example](https://i.imgur.com/Dx949oF.png)
![BloodBash verbose output example](https://i.imgur.com/vb6FmTc.png)
![BloodBash verbose output example](https://i.imgur.com/zVbyFZz.png)

## Features

- Full **SharpHound v6+** support (users, computers, groups, GPOs, OUs, domains, cert templates, Enterprise CAs, Root CAs, NTAuth stores, etc.)
- Graph construction with relationships and ACLs
- **Rich colored output** using `rich` (tables, panels, highlighted paths)
- Progress bars (`tqdm`) during loading and graph building
- Modular analysis with BloodHound-inspired queries:
  - Shortest paths to high-value targets
  - Dangerous permissions (GenericAll, Owns, ManageCA, Enroll, etc.)
  - **ADCS ESC1–ESC8 vulnerability detection** (enhanced checks for misconfigurations)
  - **GPO abuse risks** (dangerous rights on GPOs)
  - **DCSync / replication rights** on domain objects
  - **Resource-Based Constrained Delegation (RBCD)**
  - Kerberoastable accounts
  - AS-REP roastable accounts (DONT_REQ_PREAUTH)
  - Session / LocalAdmin summary
- **Verbose mode** — object type counts, user list (top 30 + summary)
- **Export** results to Markdown or JSON
- **Fast mode** (`--fast`) — skips heavy pathfinding on large datasets
- Simple custom query support (`--query`)

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/bloodbash.git
cd bloodbash

# Recommended: virtual environment
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
# or on Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Requirements

See [requirements.txt](requirements.txt):

```
networkx>=3.0
rich>=13.0
tqdm>=4.0
```

## Usage

```bash
# Run everything
python3 BloodBash.py /path/to/sharphound/json --all

# Specific analyses
python3 BloodBash.py ./sharpout --adcs --dangerous-permissions --verbose

# Export results
python3 BloodBash.py . --all --export=json

# Fast mode (skip pathfinding)
python3 BloodBash.py sharpout --all --fast
```

### Available Flags

| Flag                        | Description                                          |
|-----------------------------|------------------------------------------------------|
| `--shortest-paths`          | Show shortest attack paths to high-value targets     |
| `--dangerous-permissions`   | Dangerous ACLs on sensitive objects                  |
| `--adcs`                    | ADCS ESC1–ESC8 vulnerability checks                  |
| `--gpo-abuse`               | Detect weak GPO permissions                          |
| `--dcsync`                  | DCSync / replication rights                          |
| `--rbcd`                    | Resource-Based Constrained Delegation targets        |
| `--sessions`                | Session / LocalAdmin summary                         |
| `--kerberoastable`          | Kerberoastable accounts                              |
| `--as-rep-roastable`        | AS-REP roastable accounts                            |
| `--verbose`                 | Show detailed object type & user summary             |
| `--all`                     | Run all analyses                                     |
| `--export [md|json]`        | Export results to file (default: md)                 |
| `--fast`                    | Skip heavy pathfinding for speed                     |

If no flags are specified, the script runs in a minimal mode. Use `--all` for full analysis.

## Example Output

```
Loading JSON files... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
✓ Loaded 304 objects from 7 files
Building graph: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████| 304/304 [00:00<00:00, 71002.81node/s]
✓ Graph built: 304 nodes, 1819 edges

VERBOSE SUMMARY
┌─────────────────────────────┐
│        Object Types         │
├───────────────┬─────────────┤
│ Group         │        113  │
│ User          │         49  │
│ Computer      │         20  │
│ Certificate Template │ 63  │
│ Enterprise CA │          4  │
└───────────────┴─────────────┘

Users (49):
  • KRBTGT@PHANTOM.CORP
  • ADMINISTRATOR@PHANTOM.CORP
  ...

ADCS ESC Vulnerabilities (ESC1–ESC8)
ESC1/ESC2: USER-SPECIFIC-TEMPLATE@CORP (Enroll + weak config)
  → LOWPRIVUSER can Enroll
...
```

## Contributing

Pull requests are welcome!  
Ideas / high-priority additions:
- Full path chaining for ADCS ESC scenarios
- GPO change parsing (Scheduled Tasks, etc.)
- Shadow Credentials detection
- HTML export with embedded graphs
- `--query` DSL improvements

## License

MIT License — free to use, modify, and share.

Happy hunting! 🩸🐕

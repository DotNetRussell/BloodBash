
![BloodBash verbose output example](https://i.imgur.com/m5RVnJZ.png)

# BloodBash 🩸#️

![Run Unit Tests](https://github.com/dotnetrussell/bloodbash/actions/workflows/run-tests.yml/badge.svg)

**BloodBash v1.2.3** is a powerful, **standalone** BloodHound / SharpHound JSON analyzer written in Python.

It parses **real SharpHound collection-per-file JSON** (the format actually produced by SharpHound v6+), builds a full `networkx` directed graph (nodes + all relationships & ACLs), detects attack paths, misconfigurations, and high-impact AD vulnerabilities — **completely offline**, no Neo4j or BloodHound GUI required.

Perfect for red teamers, OSCP/CRTP/PNPT prep, quick post-collection triage, or when you only have raw SharpHound JSON dumps.

![BloodBash verbose output example](https://i.imgur.com/RRUtTD0.png)

## What's New in v1.2.3
- Fixed & hardened SharpHound collection-per-file parsing (users/, computers/, etc.)
- **Prioritized Findings** table sorted by severity (ESCs, DCSync, RBCD, etc.)
- New modules: Shadow Credentials, Password in Description, LAPS status, full GPO XML content parsing (`--gpo-content-dir`), Unconstrained/Constrained Delegation, Trust Abuse, Deep Group Nesting + cycle detection
- New CLI flags: `--owned`, `--path-from`/`--path-to`, `--inspect`, `--deep-analysis`, `--db` (SQLite persistence), `--export-bh`, `--dot`, `--indirect`, `--debug`
- Rich abuse-suggestion panels for **every** finding
- Multiple export formats + BloodHound-compatible JSON + Graphviz DOT

## Installation

```bash
git clone https://github.com/dotnetrussell/bloodbash.git
cd bloodbash

# Recommended: virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux/macOS
# Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## Requirements
`requirements.txt`:
```txt
networkx>=3.0
rich>=13.0
tqdm>=4.0
pyyaml>=6.0
```
(All other dependencies are in the Python standard library.)

## Usage

```bash
# Full analysis (recommended)
python3 BloodBash.py /path/to/sharphound/json --all

# Selective checks
python3 BloodBash.py ./sharpout --adcs --dangerous-permissions --dcsync --gpo-abuse --verbose

# Export everything
python3 BloodBash.py . --all --export=html --export-bh --dot

# Fast mode on huge datasets (skips pathfinding)
python3 BloodBash.py sharpout --all --fast

# Use SQLite cache for repeated runs
python3 BloodBash.py . --db bloodbash.db --all
```

### All Available Flags

| Flag                        | Description |
|----------------------------|-------------|
| `--all`                    | Run every analysis module |
| `--shortest-paths`         | Shortest paths to high-value targets |
| `--dangerous-permissions`  | Dangerous ACLs on high-value objects |
| `--adcs`                   | Full ADCS ESC1–ESC8 detection |
| `--gpo-abuse`              | Weak GPO permissions |
| `--dcsync`                 | DCSync / replication rights |
| `--rbcd`                   | Resource-Based Constrained Delegation |
| `--sessions`               | Sessions / LocalAdmin / RDP / DCOM summary |
| `--kerberoastable`         | Kerberoastable accounts |
| `--as-rep-roastable`       | AS-REP roastable accounts |
| `--sid-history`            | SID History abuse |
| `--unconstrained-delegation` | Unconstrained delegation |
| `--password-descriptions`  | Passwords stored in user description |
| `--password-never-expires` | PasswordNeverExpires users |
| `--password-not-required`  | PasswordNotRequired users |
| `--shadow-credentials`     | Shadow Credentials (KeyCredentialLink) |
| `--gpo-parsing`            | Basic GPO content parsing |
| `--gpo-content-dir DIR`    | Full GPO XML analysis (Scheduled Tasks, Scripts, cPassword) |
| `--constrained-delegation` | Constrained delegation |
| `--laps`                   | LAPS enabled/disabled status |
| `--verbose`                | Detailed object-type & user summary |
| `--owned USERS`            | Comma-separated owned principals → paths to them |
| `--path-from SRC`          | Arbitrary shortest paths: source principals |
| `--path-to DST`            | Arbitrary shortest paths: target principals |
| `--inspect NODES`          | Full property + edge dump for specific nodes |
| `--deep-analysis`          | Enable slow group nesting depth + cycle detection |
| `--indirect`               | Include indirect paths/permissions via groups |
| `--domain DOMAIN`          | Filter everything to a single domain |
| `--export FORMAT`          | Export results (`md`, `json`, `html`, `csv`, `yaml`) |
| `--export-bh`              | Export full graph as BloodHound-compatible JSON |
| `--dot [FILE]`             | Export key subgraph to Graphviz DOT |
| `--db FILE`                | SQLite persistence (save/load graph) |
| `--fast`                   | Skip heavy pathfinding |
| `--debug`                  | Verbose debug output |

If **no flags** are given, the tool runs a minimal default mode (verbose summary + common checks).

![BloodBash verbose output example](https://i.imgur.com/zqsjVgC.png)
![BloodBash verbose output example](https://i.imgur.com/GtGvchM.png)
![BloodBash verbose output example](https://i.imgur.com/tTHVUuy.png)

## Features

- **Accurate SharpHound v6+ parsing** (handles the real per-collection JSON files with `meta.type`)
- Full `networkx.MultiDiGraph` with all relationships & ACEs
- **Rich, colored terminal output** (tables, panels, highlighted paths)
- Progress bars + live status
- **Prioritized Findings** sorted by severity score (ESC1-ESC8 = 10, DCSync = 10, RBCD = 9, etc.)
- Detailed **abuse suggestion panels** with tools & commands for every vulnerability
- High-value target identification (Domain Admins, krbtgt, CAs, templates, etc.)
- Complete ADCS ESC1–ESC8 detection with exact conditions
- Dangerous permissions (GenericAll, ResetPassword, WriteDacl, etc.)
- GPO abuse + **full XML content analysis** (Scheduled Tasks, Scripts, cPassword)
- DCSync, RBCD, Kerberoasting, AS-REP roasting, Shadow Credentials, LAPS status, delegation types, SID History, PasswordNeverExpires / PasswordNotRequired
- Shortest & indirect paths, paths to owned principals, arbitrary custom paths
- Node inspection, group nesting depth & cycle detection
- Exports: Markdown, JSON, HTML, CSV, YAML, **BloodHound-compatible JSON**, Graphviz DOT
- SQLite database persistence (`--db`)
- Domain filtering, fast mode, debug mode

![BloodBash verbose output example](https://i.imgur.com/4rbBgDW.png)
![BloodBash verbose output example](https://i.imgur.com/ODvkG6a.png)

## Example Output (abridged)
```
────────────────────────────────────────────────────────────── ADCS ESC Vulnerabilities (ESC1–ESC8) ──────────────────────────────────────────────────────────────
[red]ESC1/ESC2[/red]: WebServerTemplate (Enroll + EnrolleeSuppliesSubject + no approval)
  → CONTOSO\Tier1Admins can Enroll
────────────────────────────────────────────────────────────── Prioritized Findings by Severity ──────────────────────────────────────────────────────────────
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity Score  ┃ Category            ┃ Details                                                                                                                                                                                                                       ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 10              │ ESC1-ESC8           │ ESC1/2 on WebServerTemplate                                                                                                                                                                                                   │
│ 10              │ DCSync              │ CONTOSO\svc_sql can DCSync on contoso.local                                                                                                                                                                                  │
└─────────────────┴─────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
Completed in 12.45 seconds
```

## Contributing
Pull requests welcome!  
High-priority ideas:
- Full ADCS attack-path chaining
- More export formats (PlantUML, Mermaid)
- Integration with BloodHound Enterprise / custom collectors
- Performance optimizations for 100k+ node domains

## License
MIT License — free to use, modify, and share for authorized security testing and red teaming only.

Happy hunting! 🩸🐕



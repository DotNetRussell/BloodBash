# BloodBash 🐾

**BloodBash** is a lightweight, standalone BloodHound JSON analyzer written in Python.  
It parses SharpHound (v6+) JSON files directly — no Neo4j, no BloodHound GUI required.

It builds a graph using `networkx`, detects object types correctly, finds attack paths, and implements several popular BloodHound-style queries such as shortest paths to high-value targets, dangerous permissions, kerberoastable accounts, and more.

Perfect for red teamers, pentest engagements, and quick AD reconnaissance when you only have raw SharpHound output.

## Features

- Supports **SharpHound v6+** JSON format (users, computers, groups, GPOs, OUs, domains, cert templates, Enterprise CAs, Root CAs, NTAuth stores, etc.)
- Builds a directed graph with relationships and ACLs
- Modular analysis with BloodHound-inspired queries:
  - Shortest paths to high-value targets
  - Dangerous permissions (GenericAll, Owns, WriteDacl, ManageCA, Enroll, etc.)
  - Unconstrained delegation
  - Kerberoastable accounts
  - AS-REP roastable accounts (DONT_REQ_PREAUTH)
  - High-value target listing
- Verbose summary mode (object types, users, etc.)
- No external dependencies beyond `networkx`

## Installation

```bash
# Clone the repo
git clone https://github.com/DotNetRussell/BloodBash.git
cd BloodBash

# Recommended: use a virtual environment
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt
```

## Requirements

- Python 3.8+
- See [requirements.txt](#requirementstxt) for exact dependencies

## Usage

```bash
# Basic usage (run all analyses)
python3 BloodBash /path/to/sharphound/json

# Specific analyses
python3 BloodBash ./sharpout --dangerous-permissions
python3 BloodBash . --shortest-paths --kerberoastable --verbose

# Run everything explicitly
python3 BloodBash sharpout --all

# Show only high-value targets
python3 BloodBash . --high-value
```

### Available Flags

| Flag                        | Description                                      |
|-----------------------------|--------------------------------------------------|
| `--shortest-paths`          | Show shortest attack paths to high-value targets |
| `--dangerous-permissions`   | Show dangerous ACLs on sensitive objects         |
| `--unconstrained-delegation`| List objects with unconstrained delegation       |
| `--kerberoastable`          | List kerberoastable user accounts                |
| `--as-rep-roastable`        | List AS-REP roastable accounts                   |
| `--high-value`              | List high-value targets only                     |
| `--verbose`                 | Show detailed object type and user summary       |
| `--all`                     | Run all available analyses                       |

If no flags are provided, **all** analyses run by default (same as `--all`).

## Examples

```bash
# Quick ADCS / PKI abuse check
python3 BloodBash sharpout --dangerous-permissions --high-value

# Kerberoasting recon
python3 BloodBash . --kerberoastable --as-rep-roastable

# Full report with paths
python3 BloodBash sharpout --shortest-paths --verbose --all
```

## Output Example

```
[+] Processed 42 JSON files → 1247 objects loaded
[+] Graph: 1247 nodes, 5832 edges

=== High-Value Targets ===
  • DOMAIN ADMINS@CORP (Group)
  • KRBTGT@CORP (User)
  • PHANTOM-DC01-CA@CORP (Enterprise CA)
  ...

=== Dangerous Permissions on High-Value Objects ===
DOMAIN ADMINS@CORP (Group):
  • LOWPRIVUSER --[GenericAll]--> DOMAIN ADMINS@CORP

PHANTOM-DC01-CA@CORP (Enterprise CA):
  • SOMEUSER --[ManageCA]--> PHANTOM-DC01-CA@CORP
  ...
```

## Contributing

Pull requests welcome!  
Especially interested in:
- More BloodHound-style queries (RBCD, GPO abuse, ESC1–8 specific checks)
- Better path formatting / export to text/JSON
- Colorized output (using `rich` or `termcolor`)

## License

MIT License — feel free to use, modify, and share.

Happy hunting! 🩸🐕

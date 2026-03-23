# evidence2html

Turn pen-test evidence files into a single, self-contained HTML report.

Drop your tool outputs (Nmap XML, ffuf JSON, testssl, sqlmap logs, banners, …)
into a folder, run one command, get a styled report you can hand in or archive.

## Requirements

- Python 3.8+
- `xsltproc` — ships with Kali; on Debian/Ubuntu: `sudo apt install xsltproc`

No pip packages needed. Everything runs on stdlib.

## Quick start

```bash
git clone https://github.com/CosmicSlothOracle/evididencetohtml.git
cd evididencetohtml

# point it at your evidence directory
python3 evidence2html.py /path/to/evidence/

# output: report.html + merged_scan.xml in the current directory
```

## Usage

```
python3 evidence2html.py [OPTIONS] [NMAP_XML ...]
```

| Flag | Default | What it does |
|------|---------|--------------|
| `-e DIR` | auto-detected | Evidence directory |
| `-o FILE` | `report.html` | HTML output path |
| `-x FILE` | `merged_scan.xml` | Intermediate merged XML |
| `-s FILE` | `cosmic_clean.xsl` | XSL stylesheet |
| `-n FILE` | — | Nuclei JSONL to inject |
| `-a DIR` | — | Directory with ASCII art `.txt` files |

If the first positional argument is a directory, it is treated as the evidence
dir. Nmap XMLs inside it (`scan_*.xml`, `nmap*.xml`) are picked up automatically.

### Examples

```bash
# evidence only, no Nmap scans
python3 evidence2html.py ./my_evidence/

# evidence + explicit Nmap XMLs
python3 evidence2html.py -e ./my_evidence/ scan_tcp.xml scan_udp.xml

# custom output name
python3 evidence2html.py -o pentest_report.html ./my_evidence/

# include Nuclei results
python3 evidence2html.py -e ./my_evidence/ -n nuclei_output.json

# include personalized ASCII art
python3 evidence2html.py -a ./ascii_arts/ ./my_evidence/
```

## Evidence file naming

The script auto-detects tool outputs by filename prefix:

| Prefix | Tool |
|--------|------|
| `evidence_ffuf_*` | ffuf |
| `evidence_sqlmap_*` | sqlmap |
| `evidence_testssl_*` | testssl.sh |
| `evidence_nuclei_*` | nuclei |
| `evidence_nxc_*` / `evidence_cme_*` | netexec / crackmapexec |
| `evidence_msf_*` | metasploit |
| `evidence_subfinder_*` | subfinder |
| `evidence_httpx_*` | httpx |
| `evidence_dns_*` | dig |
| `evidence_tshark_*` | tshark |
| `evidence_nikto_*` | nikto |
| `evidence_burp_*` | burp |
| `banner_*` | nc/bash |
| `*.hex` | nc/xxd |

Any file matching `evidence_*` will be included regardless of prefix — unknown
tools just won't get structured parsing.

## ASCII art

Use `-a` to point at a directory of `.txt` files. Each file becomes a named art
block in the report, keyed by filename (without extension). Put one file per
person or per target — whatever makes sense for your workflow.

```
ascii_arts/
├── alice.txt
├── bob.txt
└── cosmic_header.txt
```

## How it works

1. **Collect** — reads all matching files from the evidence directory, deduplicates, classifies by tool.
2. **Merge** — if Nmap XMLs are provided, merges hosts/ports/scripts across scans into one XML. Otherwise builds a minimal XML envelope.
3. **Inject** — structured findings (ffuf hits, SQLi confirmations, TLS vulns, …) are parsed and embedded as metadata.
4. **Transform** — `xsltproc` applies `cosmic_clean.xsl` to produce the final HTML with embedded styles and fonts.

## License

MIT

# evidence2html

Turn pen-test evidence files into a single, self-contained HTML report.

Drop your tool outputs into a folder, run one command, answer a few prompts, get a styled report.

## Requirements

- Python 3.8+
- `xsltproc` — ships with Kali; on Debian/Ubuntu: `sudo apt install xsltproc`

No pip packages. Everything runs on stdlib.

## Quick start

```bash
git clone https://github.com/CosmicSlothOracle/evididencetohtml.git
cd evididencetohtml

python3 evidence2html.py
```

The script will prompt you for the evidence directory, then do the rest:
- Auto-detects Nmap XMLs and Nuclei results
- Collects and deduplicates evidence files
- Loads ASCII art (if present in `ascii_arts/` subdir)
- Merges everything into one XML
- Transforms to HTML with xsltproc

Output: `report.html` + `merged_scan.xml` in your current directory.

## Workflow

1. Organize evidence files in a folder (or multiple folders):
   ```
   my_evidence/
   ├── scan_tcp.xml
   ├── scan_udp.xml
   ├── nuclei.json
   ├── evidence_ffuf_results.json
   ├── evidence_sqlmap_findings.txt
   ├── banner_ssh.txt
   └── …
   ```

2. Add optional personalized ASCII art:
   ```
   ascii_arts/
   ├── alice.txt
   ├── bob.txt
   └── cosmic_header.txt
   ```

3. Run:
   ```bash
   python3 evidence2html.py
   ```

4. Answer the prompts:
   - Evidence directory path
   - Output HTML filename (default: `report.html`)
   - Whether to include `nuclei.json` if found

5. Done. Open `report.html`.

## Evidence file naming

Files are auto-detected and classified by prefix. The script looks for:

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

Any file matching `evidence_*` is included regardless. Unknown prefixes won't get structured parsing, but raw content appears in the report.

## How it works

1. **Collect** — reads all matching files from the evidence directory, deduplicates by content hash, classifies by tool.
2. **Parse** — structured findings are extracted from JSON/text outputs (ffuf, SQLi, testssl, netexec, metasploit, subdomains).
3. **Merge** — if Nmap XMLs exist, merges hosts/ports/scripts into one XML. Otherwise builds a minimal envelope just for evidence.
4. **Inject** — ASCII art (if present) and structured findings are embedded as XML metadata.
5. **Transform** — `xsltproc` applies `cosmic_clean.xsl` to produce final HTML with embedded styles and fonts.

## License

MIT

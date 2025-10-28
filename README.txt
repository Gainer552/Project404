Project404

Overview

Project404 is a lightweight, signature-free, behavior-driven file-scanner for Arch Linux and similar GNU/Linux systems. It inspects individual files for indicators commonly used by obfuscation techniques (packing, high entropy, long encoded blobs, script-based obfuscation patterns, and living-off-the-land keywords) and reports findings in a human-friendly, colorized table.

Project404 is intended as a defensive research and incident-response aid. It is implemented as a single portable Bash script (project404.sh) using standard GNU/Linux utilities (file, strings, readelf, grep, awk, od, dd, etc.).

Key features

- Signature-free heuristics (entropy, string profile, encoded blob detection).
- Multi-category reporting (Packers/Crypters, HighEntropy, LongEncodedBlobs, ScriptObfuscation, LOTL/LOLBAS, ELF SuspiciousSections, FewPrintableStrings).
- Word-boundary LOTL detection to reduce false positives.
- Multi-line-aware Base64 detection with hex/base64 disambiguation.
- Small-file exclusions for the "few printable strings" heuristic.
- Colorized, human-readable table output.
- Compact single-file deployment and easy tuning for thresholds.

Intended use cases

- Quick investigative checks on suspicious files in incident response.
- Local development/testing of detection heuristics.
- Integration into lightweight endpoint checks or monitoring scripts.
- Educational demonstrations of heuristic-based static analysis.

Limitations & important caveats

- Static-only analysis: Project404 inspects files on disk and reports indicators. It does not perform dynamic, runtime, or memory-based analysis and therefore can miss fileless techniques.
- Heuristic nature: Detections are probabilistic indicators, not proof of maliciousness. Manual review and complementary telemetry (process, network, EDR) are required for confident decisions.
- Resource constraints: Some checks (entropy sampling, readelf, strings) read portions of files. Very large files (multi-GB) may be slow; the script uses a bounded window for multi-line base64 checks to avoid slurping entire files, but you should tune the COLLAPSE_LIMIT_BYTES for your environment.
- Not a replacement for full EDR/AV solutions: Project404 is a tool for defenders and researchers, not an antivirus product.

Installation (Arch Linux)

1. Clone or copy the project files into a safe directory (e.g., ~/project404):

   git clone https://github.com/Gainer552/Project404.git

2. Make the script executable and (optionally) move it into a bin directory:

   chmod +x project404.sh

3. Ensure required tools are installed (most are available by default on Arch):

   sudo pacman -Syu file grep coreutils gawk binutils openssl

Usage

Run the script and provide an absolute file path when prompted: sudo /usr/local/bin/project404.sh

The script will prompt:

Enter full path of file to scan: /path/to/suspicious/file

It prints a colorized table of one-line indicators for categories that matched. At the end the script prints entropy, file size, and MIME type.

Example workflow

1. Copy a suspicious file into an isolated analysis directory (or work on a copy):

   mkdir -p ~/analysis && cp /path/to/file ~/analysis/

2. Run Project404 against the copy:

   sudo project404.sh
   Enter full path of file to scan: ~/analysis/file

3. Review the reported categories and notes, then follow your incident response playbook (sandboxing, memory analysis, triage, containment).

Configuration & tuning

Project404 has a small set of tuned thresholds at the top of the script that you can adjust:

- SAMPLE_BYTES: number of bytes sampled to compute entropy (default 65536)
- ENTROPY_THRESHOLD: entropy above which a file is considered "high" (default 7.5)
- B64_MIN_LEN / HEX_MIN_LEN: minimum contiguous run length for encoded blob detection
- MIN_SIZE_FOR_STRING_PROFILE: minimum size to apply the few-strings heuristic
- COLLAPSE_LIMIT_BYTES: how many bytes to read when collapsing newlines for base64/hex detection (default 4 MiB)

Adjust these values for your environment; e.g., reduce SAMPLE_BYTES for faster runs on SSDs or increase COLLAPSE_LIMIT_BYTES for very large artifacts.

Testing

A small testset of benign samples can be created to validate the heuristics. Example categories to test:

- High-entropy binary (dd if=/dev/urandom ...)
- Long base64 blob (openssl rand -base64 ...)
- Long hex blob (xxd -p ...)
- Script with inert decoding patterns (commented out base64/eval lines)
- Text file with LOTL keywords
- Compiled ELF with a custom section name (compile a C file with a custom section attribute)

Use the sample files to confirm the scanner reports the expected categories and tune thresholds to reduce false positives.

Legal disclaimer (read carefully)

Project404 is provided for defensive research, education, and incident response only. By using Project404 you agree to the following terms:

1. No guarantees. Project404 is provided "as-is," without warranty of any kind. The authors and contributors disclaim all warranties, express or implied, including but not limited to merchantability, fitness for a particular purpose, and non-infringement.

2. Limited liability. Under no circumstances shall the authors, contributors, or distributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising in any way out of the use of this software, even if advised of the possibility of such damage.

3. Authorized use only. You are responsible for ensuring you have explicit authorization to analyze any files or systems. Do not use Project404 on systems or data for which you do not have permission. The authors are not responsible for misuse.

4. No offensive capability. Project404 intentionally avoids implementing offensive techniques or providing exploit code. It is designed strictly for detection and defensive analysis. If you require dynamic or memory analysis, use reputable commercial or research sandbox tools.

5. Export and legal compliance. You are responsible for complying with all applicable laws, export controls, and regulations when using or distributing Project404.

6. Indemnification. You agree to indemnify and hold harmless the authors and contributors from any claims, damages, losses, liabilities, and expenses arising from your use of Project404.
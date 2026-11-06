#!/usr/bin/env python3
"""Checks a repository for what recent supply chain attacks hide in, using only the standard library.

Each check exists because of a technique seen in the wild:

- Invisible Unicode in source. Worms in editor extensions have hidden payloads in characters that no
  review tool shows, and bidirectional controls make code read differently from how it compiles.
- Things that run without being asked: an editor task that runs on folder open, a tracked Git hooks
  directory, a dev container that downloads at creation, a Git filter driver, an agent's server config.
- Package install hooks, the trigger used by self-replicating registry worms, and `binding.gyp`, which
  runs a build with no install script declared at all.
- CI trust boundaries: `pull_request_target`, untrusted event text pasted into a shell, missing
  least-privilege permissions, and `curl | sh`.
- Credentials committed to the tree.

It reads tracked files only, runs nothing from the repository, and needs no network. Add a line
containing `repo-guard: allow` to a file to accept what this finds on that line, and say why there.

Usage: repo_guard.py [DIRECTORY] [--strict]
The exit code is 1 if there are errors, or with --strict, warnings too.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ERROR, WARNING = "error", "warning"

# Zero-width characters, bidirectional controls, invisible operators and tag characters, and the
# variation selector ranges used to smuggle bytes.
INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufe00-\ufe0f"
    "\U000e0000-\U000e0fff\U000f0000-\U000ffffd\U00100000-\U0010fffd\ue000-\uf8ff]"
)
# A byte order mark at the very start of a file, and the joiners in emoji sequences, are ordinary.
PROSE_EXTENSIONS = {".md", ".txt", ".rst", ".tex", ".typ", ".html", ".htm", ".svg"}
# In prose, only what changes how text reads is a concern. Joiners and emoji selectors are fine there.
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\U000e0000-\U000e0fff]")
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".wasm", ".r1cs", ".wtns", ".jar",
    ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".webm", ".webp", ".bin", ".exe", ".dll", ".so", ".dylib",
    ".a", ".o", ".class", ".pyc", ".nds", ".sav", ".mov", ".keystore",
}
SECRETS = [
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "a GitHub personal access token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "a GitHub fine-grained token"),
    (re.compile(r"\bgh[osu]_[A-Za-z0-9]{36}\b"), "a GitHub app or OAuth token"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "a GitLab token"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "an npm token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "an AWS access key"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "a Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"), "a private key"),
    (re.compile(r"https?://[^/\s:@'\"]+:[^/\s@'\"]{8,}@[^\s'\"]+"), "a URL with a password in it"),
]
FETCH_AND_RUN = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
FETCHES = re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr|base64\s+-d|eval)\b")
UNTRUSTED_EVENT = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
    r"|head_ref)[^}]*\}\}"
)
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly")


class Findings:
    def __init__(self):
        self.items = []

    def add(self, level, path, line, message):
        self.items.append((level, path, line, message))


def tracked_files(root):
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True)
        names = [n for n in out.stdout.decode("utf-8", "surrogateescape").split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    return names


def read_text(path):
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192] or len(data) > 5_000_000:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def allowed(line):
    return "repo-guard: allow" in line


def check_text(name, text, findings):
    suffix = Path(name).suffix.lower()
    lines = text.split("\n")
    # This file names these patterns, and so do its tests.
    is_guard = Path(name).name in ("repo_guard.py", "test_repo_guard.py")
    pattern = BIDI if suffix in PROSE_EXTENSIONS else INVISIBLE
    for number, line in enumerate(lines, 1):
        if allowed(line) or (number > 1 and allowed(lines[number - 2])):
            continue
        scan = line.lstrip("\ufeff") if number == 1 else line
        if not is_guard:
            match = pattern.search(scan)
            if match:
                findings.add(ERROR, name, number, f"invisible or bidirectional character U+{ord(match.group()):04X}")
            for secret, what in SECRETS:
                if secret.search(line):
                    findings.add(ERROR, name, number, f"what looks like {what}")


def check_auto_run(name, text, findings):
    lower = name.lower()
    parts = Path(name).parts
    if lower.endswith(".vscode/tasks.json") and re.search(r'"runOn"\s*:\s*"folderOpen"', text):
        findings.add(ERROR, name, 0, "an editor task runs by itself when the folder is opened")
    if parts and parts[0] in (".githooks", ".husky"):
        if FETCHES.search(text):
            findings.add(ERROR, name, 0, "a tracked Git hook downloads or decodes something")
        else:
            findings.add(WARNING, name, 0, "a tracked Git hook, so check that nothing points core.hooksPath at it silently")
    if ".devcontainer" in parts and FETCHES.search(text):
        findings.add(ERROR, name, 0, "a dev container downloads or decodes something when it is created")
    if Path(name).name == ".gitattributes" and re.search(r"\bfilter=(?!lfs\b)", text):
        findings.add(ERROR, name, 0, "a Git filter other than LFS, which runs code on checkout if it is configured")
    if Path(name).name in (".mcp.json", "mcp.json"):
        findings.add(WARNING, name, 0, "an agent server config, which starts programs when an agent opens the repository")
    if Path(name).name == ".gitmodules" and re.search(r"url\s*=\s*(?:ext::|[^\s]*--upload-pack)", text):
        findings.add(ERROR, name, 0, "a submodule URL that runs a command")
    if Path(name).name == "binding.gyp":
        findings.add(WARNING, name, 0, "a native build, which package managers run on install with no script declared")


def check_package_json(name, text, findings):
    if Path(name).name != "package.json":
        return
    try:
        manifest = json.loads(text)
    except ValueError:
        return
    scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
    if not isinstance(scripts, dict):
        return
    for hook in INSTALL_HOOKS:
        command = scripts.get(hook)
        if isinstance(command, str):
            level = ERROR if FETCHES.search(command) else WARNING
            findings.add(level, name, 0, f"the `{hook}` script runs on install: {command[:60]}")


def check_workflow(name, text, findings):
    if not name.startswith(".github/workflows/") or not name.endswith((".yml", ".yaml")):
        return
    lines = text.split("\n")
    if re.search(r"^\s*-?\s*pull_request_target\b|^on:\s*\[?.*pull_request_target", text, re.M):
        findings.add(WARNING, name, 0, "`pull_request_target` runs with secrets on events from forks, so it must never check out their code")
    if not re.search(r"^\s*permissions\s*:", text, re.M):
        findings.add(ERROR, name, 0, "no `permissions:`, so the token gets whatever the repository default is")
    if re.search(r"^\s*permissions\s*:\s*write-all", text, re.M):
        findings.add(ERROR, name, 0, "`permissions: write-all` is the opposite of least privilege")
    in_run = False
    run_indent = 0
    for number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        match = re.match(r"(-\s+)?run\s*:(.*)$", stripped)
        if match:
            in_run = True
            run_indent = indent
            body = match.group(2)
        elif in_run and stripped and indent <= run_indent:
            in_run = False
            body = ""
        else:
            body = line if in_run else ""
        if allowed(line):
            continue
        if body:
            if UNTRUSTED_EVENT.search(body):
                findings.add(ERROR, name, number, "text from an event goes straight into a shell, so pass it through `env:`")
            if FETCH_AND_RUN.search(body):
                findings.add(ERROR, name, number, "downloads a script and runs it unverified")
        uses = re.search(r"uses:\s*([^\s#]+)", line)
        if uses:
            ref = uses.group(1)
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            version = ref.split("@", 1)[1] if "@" in ref else ""
            if not re.fullmatch(r"[0-9a-f]{40}", version):
                findings.add(WARNING, name, number, f"`{ref}` is not pinned to a commit, and a tag can be moved")


def scan(root):
    root = Path(root)
    findings = Findings()
    names = tracked_files(root)
    for name in names:
        if Path(name).suffix.lower() in BINARY_EXTENSIONS:
            continue
        text = read_text(root / name)
        if text is None:
            continue
        check_text(name, text, findings)
        check_auto_run(name, text, findings)
        check_package_json(name, text, findings)
        check_workflow(name, text, findings)
    return findings


def main(argv):
    strict = "--strict" in argv
    positional = [a for a in argv if not a.startswith("--")]
    findings = scan(positional[0] if positional else ".")
    for level, path, line, message in sorted(findings.items, key=lambda i: (i[0], i[1], i[2])):
        place = f"{path}:{line}" if line else path
        print(f"{level}: {place}: {message}")
    errors = sum(1 for i in findings.items if i[0] == ERROR)
    warnings = len(findings.items) - errors
    print(f"repo guard: {errors} errors, {warnings} warnings")
    return 1 if errors or (strict and warnings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

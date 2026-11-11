from dataclasses import asdict, dataclass
from pathlib import Path
import re

@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    path: str = ""
    evidence: str = ""
    recommendation: str = ""
    def to_dict(self): return asdict(self)

PATTERNS = [("RD001", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")), ("RD002", re.compile(r"(?i)(?:api[_-]?key|secret|access[_-]?token)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-]{16,}")), ("RD003", re.compile(r"\\bgh[pousr]_[A-Za-z0-9]{30,}\\b"))]
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env", ".md", ".txt", ".sh", ".html", ".go", ".rs", ".java", ".rb"}

def scan_repository(directory):
    root = Path(directory).expanduser().resolve()
    if not root.is_dir(): raise ValueError(f"Not a directory: {root}")
    files = [p for p in root.rglob("*") if p.is_file() and not any(x in SKIP for x in p.parts) and (p.suffix.lower() in SUFFIXES or p.name.startswith(".env"))]
    rels = {p.relative_to(root).as_posix() for p in files}
    names = {p.name.lower() for p in root.iterdir() if p.is_file()}
    out = []
    def add(rule, severity, title, msg, path, evidence, fix): out.append(Finding(rule,severity,title,msg,path,evidence,fix))
    if not any(n.startswith("readme") for n in names): add("RD100","high","README missing","No top-level README found.","README.md","File not found.","Add purpose, installation, usage, and contribution instructions.")
    if not any(n.startswith("license") or n == "copying" for n in names): add("RD101","medium","License missing","No top-level license file found.","LICENSE","File not found.","Choose and add an appropriate open-source license.")
    if not names.intersection({"pyproject.toml","requirements.txt","package.json","go.mod","cargo.toml","pom.xml"}): add("RD102","low","Project manifest missing","No common project manifest detected.","","Checked common language manifests.","Add the manifest for your language and build system.")
    if not any(p.startswith(".github/workflows/") for p in rels): add("RD103","medium","CI workflow missing","No GitHub Actions workflow found.",".github/workflows/","No workflow YAML file found.","Add automated tests and quality checks for pushes and pull requests.")
    if not any(p.startswith(("tests/","test/")) or Path(p).name.startswith("test_") for p in rels): add("RD104","medium","Tests missing","No conventional test directory or test file found.","tests/","No tests found.","Add automated tests for important behavior and edge cases.")
    for p in files:
        try:
            if p.stat().st_size > 1000000: continue
            lines = p.read_text(encoding="utf-8",errors="ignore").splitlines()
        except OSError: continue
        rel = p.relative_to(root).as_posix()
        for number,line in enumerate(lines,1):
            for rule,pattern in PATTERNS:
                if pattern.search(line): add(rule,"critical","Possible exposed secret","A secret-like pattern matched; value redacted.",rel,f"Pattern matched on line {number}; value not stored.","Verify the match, revoke exposed credentials, and use environment variables or a secret manager.")
    order = {"critical":0,"high":1,"medium":2,"low":3}
    return sorted(out,key=lambda f:(order.get(f.severity,9),f.rule_id,f.path))

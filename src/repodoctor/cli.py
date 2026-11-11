import argparse
from pathlib import Path
import sys
from . import __version__
from .scanner import scan_repository
from .reporters import markdown_report,json_report,sarif_report,summary

def main(argv=None):
    p=argparse.ArgumentParser(prog="repodoctor",description="Audit a local repository for common health and security issues.")
    p.add_argument("--version",action="version",version=f"%(prog)s {__version__}")
    sub=p.add_subparsers(dest="command",required=True); s=sub.add_parser("scan",help="Scan a local repository")
    s.add_argument("path",nargs="?",default="."); s.add_argument("--format",choices=("text","markdown","json","sarif"),default="text"); s.add_argument("--output"); s.add_argument("--fail-on",choices=("never","low","medium","high","critical"),default="never")
    a=p.parse_args(argv)
    try: findings=scan_repository(a.path)
    except (ValueError,OSError) as e: print(f"RepoDoctor: {e}",file=sys.stderr); return 2
    target=str(Path(a.path).resolve())
    if a.format=="json": out=json_report(findings,target)
    elif a.format=="sarif": out=sarif_report(findings)
    elif a.format=="markdown": out=markdown_report(findings,target)
    else:
        st=summary(findings); out=f"RepoDoctor | {target}\nHealth score: {st['score']}/100 | {st['total']} finding(s)\n"
        for f in findings: out+=f"\n[{f.severity.upper()}] {f.rule_id} {f.title}\n  {f.path}: {f.message}\n  Fix: {f.recommendation}\n"
        if not findings: out+="\nNo findings. This is not a guarantee of security.\n"
    if a.output: Path(a.output).write_text(out,encoding="utf-8")
    else: print(out)
    if a.fail_on!="never":
        order=["critical","high","medium","low"]; threshold=order.index(a.fail_on)
        if any(order.index(f.severity)<=threshold for f in findings if f.severity in order): return 1
    return 0

if __name__=="__main__": raise SystemExit(main())

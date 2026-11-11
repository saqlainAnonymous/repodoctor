import json

def summary(findings):
    counts={s:sum(f.severity==s for f in findings) for s in ("critical","high","medium","low","info")}
    score=max(0,100-counts["critical"]*30-counts["high"]*15-counts["medium"]*8-counts["low"]*3)
    return {"score":score,"total":len(findings),"counts":counts}

def markdown_report(findings,target):
    s=summary(findings); lines=[f"# RepoDoctor report: {target}","",f"**Health score: {s['score']}/100** · **Findings: {s['total']}**","","| Severity | Count |","|---|---:|"]
    lines += [f"| {k.title()} | {v} |" for k,v in s["counts"].items()]; lines += ["","## Findings"]
    for f in findings: lines += ["",f"### [{f.rule_id}] {f.title} ({f.severity.upper()})","",f.message,"",f"- Path: `{f.path or '.'}`",f"- Evidence: {f.evidence}",f"- Recommendation: {f.recommendation}"]
    if not findings: lines.append("No findings. This does not guarantee the repository is secure.")
    return "\n".join(lines)+"\n"

def json_report(findings,target): return json.dumps({"tool":"RepoDoctor","target":target,"summary":summary(findings),"findings":[f.to_dict() for f in findings]},indent=2)

def sarif_report(findings):
    rules={f.rule_id:{"id":f.rule_id,"shortDescription":{"text":f.title}} for f in findings}; results=[]
    for f in findings:
        r={"ruleId":f.rule_id,"level":"error" if f.severity in ("critical","high") else "warning","message":{"text":f.message+" Fix: "+f.recommendation}}
        if f.path: r["locations"]=[{"physicalLocation":{"artifactLocation":{"uri":f.path}}}]
        results.append(r)
    return json.dumps({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"RepoDoctor","rules":list(rules.values())}},"results":results}]},indent=2)

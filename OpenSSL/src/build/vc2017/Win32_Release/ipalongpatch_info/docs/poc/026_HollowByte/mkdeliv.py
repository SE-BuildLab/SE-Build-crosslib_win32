#!/usr/bin/env python3
"""Common helper for producing the IPALongPatch PoC deliverables:
log (UTF-8 with BOM, LF), report fragment (markdown) and JSON record."""
import json, os, datetime, re

LOGDIR = "/home/user/work/deliver/ipalongpatch_info/logs"
RESDIR = "/home/user/work/poc/results"
ENV = "/home/user/work/poc/ENV_HEADER.txt"

def fmt(ts):
    return f"{ts[0:4]}/{ts[4:6]}/{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}"

class Deliv:
    def __init__(self, nnn, cve, info, d):
        self.nnn, self.cve, self.info, self.d = nnn, cve, info, d
        self.out = d + "/out"
        self.start = open(self.out + "/START_JST.txt").read().strip()
        self.L = []
        self.R = {}   # section -> list of items
        self.L.append(open(ENV).read().rstrip("\n")); self.L.append("")
        self.L.append(f"Verification start: {fmt(self.start)} (JST)"); self.L.append("")
        self.L.append(f"Item {nnn} of 033: {cve} - {info}"); self.L.append("")
    # ---- log helpers ----
    def H(self, title):
        self.L.append(f"== {title} =="); self.L.append("")
    def P(self, en, ja):
        self.L += [en, "", ja, ""]
    def CMD(self, title, cmd, text):
        self.L.append(f"--- {title} ---")
        if cmd:
            self.L.append("$ " + cmd)
        self.L.append(text.rstrip("\n")); self.L.append("")
    def rd(self, name, head=None, tail=None, grep=None, maxlines=None):
        t = open(os.path.join(self.out, name), errors="replace").read().rstrip("\n").split("\n")
        if grep:
            t = [l for l in t if re.search(grep, l)]
        if head is not None and tail is not None and len(t) > head + tail + 1:
            t = t[:head] + [f"... ({len(t)-head-tail} lines omitted) ..."] + t[-tail:]
        if maxlines is not None and len(t) > maxlines:
            t = t[:maxlines] + [f"... ({len(t)-maxlines} more lines omitted) ..."]
        return "\n".join(t)
    # ---- report helpers ----
    def RP(self, section, en, ja):
        self.R.setdefault(section, []).append((en, ja))
    def RC(self, section, code):
        self.R.setdefault(section, []).append("```\n" + code.rstrip("\n") + "\n```")
    def finish(self, verdict, verdict_en, verdict_ja, J):
        end_dt = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9)))
        end = end_dt.strftime("%Y%m%d_%H%M%S")
        sd = datetime.datetime.strptime(self.start, "%Y%m%d_%H%M%S"); ed = datetime.datetime.strptime(end, "%Y%m%d_%H%M%S")
        dur = ed - sd; dur_s = f"{dur.days*24 + dur.seconds//3600:02d}:{(dur.seconds%3600)//60:02d}:{dur.seconds%60:02d}"
        logname = f"{self.start}_{self.nnn}of033_{self.cve}_{self.info}.log"
        self.L.append(f"Verification end: {fmt(end)} (JST)")
        self.L.append(f"Duration: {dur_s}"); self.L.append("")
        self.L.append(f"Verdict: {verdict}")
        self.L.append("EN: " + verdict_en)
        self.L.append("JA: " + verdict_ja)
        text = "\n".join(self.L) + "\n"
        os.makedirs(LOGDIR, exist_ok=True)
        with open(os.path.join(LOGDIR, logname), "wb") as f:
            f.write(b"\xef\xbb\xbf" + text.encode("utf-8"))
        # report
        order = ["Vulnerability mechanism (as observed in the code)", "PoC design",
                 "Observed behaviour BEFORE the patch (evidence excerpts)", "Observed behaviour AFTER the patch",
                 "Regression check", "How to reproduce manually (step-by-step commands a human can run)", "Limitations / notes"]
        R = [f"# {self.nnn}/033 {self.cve} — {self.info}", "",
             f"Log file: `{logname}` (in {LOGDIR}/). Verification {fmt(self.start)}–{fmt(end)} (JST), verdict **{verdict}**.", "",
             f"ログファイル: `{logname}` ({LOGDIR}/ 配下)。検証 {fmt(self.start)}〜{fmt(end)} (JST)、判定 **{verdict}**。", ""]
        for sec in order:
            R.append("## " + sec); R.append("")
            for it in self.R.get(sec, []):
                if isinstance(it, tuple):
                    R += [it[0], "", it[1], ""]
                else:
                    R += [it, ""]
        open(f"{RESDIR}/{self.nnn}_report.md", "w", encoding="utf-8").write("\n".join(R) + "\n")
        base = {"nnn": self.nnn, "cve": self.cve, "cveinfo": self.info, "log_file": logname,
                "start_jst": fmt(self.start) + " (JST)", "end_jst": fmt(end) + " (JST)", "duration": dur_s, "verdict": verdict}
        base.update(J)
        keys = ["nnn","cve","cveinfo","log_file","start_jst","end_jst","duration","verdict","before_en","before_ja","after_en","after_ja",
                "method_en","method_ja","regression_en","regression_ja","tools","poc_files","limitations_en","limitations_ja"]
        missing = [k for k in keys if k not in base]
        assert not missing, missing
        json.dump({k: base[k] for k in keys}, open(f"{RESDIR}/{self.nnn}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("log:", os.path.join(LOGDIR, logname)); print("end:", fmt(end), "duration:", dur_s)

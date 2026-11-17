"""Incident report: evidence-aware detector selection, ATT&CK mapping, safe HTML."""

import json
import os
import shutil
import tempfile
import unittest
from html.parser import HTMLParser

from keto.cli import main
from keto.framework.context import Context
from keto.report import ATTACK, RULES, build, evidence_kind, to_html
from keto.testing.synth import build_all

TMP = None


def setUpModule():
    global TMP
    TMP = tempfile.mkdtemp(prefix="keto-report-")
    build_all(TMP)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class _Checker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.scripts, self.errors = [], 0, []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts += 1
        if tag not in ("meta", "br", "hr", "img", "link", "input"):
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(tag)
        else:
            self.stack.pop()


class ReportTests(unittest.TestCase):
    def test_rules_reference_known_techniques(self):
        from keto.framework.plugin import PLUGINS, load_plugins
        load_plugins()
        for r in RULES:
            self.assertIn(r.plugin, PLUGINS)
            for t in r.attack:
                self.assertIn(t, ATTACK, r.plugin)

    def test_sigma_export(self):
        from keto.rules import sigma
        out = os.path.join(TMP, "sigma")
        paths = sigma.write_all(out)
        self.assertEqual(len(paths), len(sigma.RULES))
        self.assertEqual(len({r["id"] for r in sigma.RULES}), len(sigma.RULES))
        try:
            import yaml
        except ImportError:
            yaml = None
        for p in paths:
            with open(p, encoding="utf-8") as fh:
                text = fh.read()
            for key in ("title:", "id:", "logsource:", "detection:", "condition:", "level:", "attack.t"):
                self.assertIn(key, text, p)
            if yaml is not None:
                doc = yaml.safe_load(text)
                self.assertTrue(all(isinstance(v, dict) for k, v in doc["detection"].items() if k != "condition"))

    def test_vram_report(self):
        with Context(image=os.path.join(TMP, "synthetic.keto"),
                     host_image=os.path.join(TMP, "synthetic_host.lime")) as ctx:
            self.assertEqual(evidence_kind(ctx), "vram")
            rep = build(ctx)
        self.assertEqual([c for c in rep["coverage"] if c["status"] == "error"], [])
        titles = {f["title"] for f in rep["findings"]}
        for must in ("Executable GPU code in writable GPU memory", "GPU kernel launched from unknown or unsafe code",
                     "Cryptomining / password-cracking GPU workload", "GPU DMA moving data out of VRAM",
                     "Host executable, script stager, shellcode or file system hidden in GPU memory",
                     "GPU channel present in memory but absent from the scheduler"):
            self.assertIn(must, titles)
        ids = {t["id"] for t in rep["attack"]}
        self.assertTrue({"T1620", "T1496", "T1564", "T1005"} <= ids)
        sev = [f["severity"] for f in rep["findings"]]
        self.assertEqual(sev, sorted(sev, key=lambda s: ["critical", "high", "medium", "low", "info"].index(s)))
        self.assertNotIn("nvidia.artifactscan", {c["plugin"] for c in rep["coverage"]})  # host-only detector

    def test_html_is_well_formed_and_escaped(self):
        rep = {"tool": "t", "generated_utc": "now", "duration_s": 0, "summary": {"critical": 0, "high": 1, "medium": 0,
                                                                                 "low": 0, "info": 0},
               "case": {"image": "<script>alert(1)</script>"}, "attack": [],
               "findings": [{"severity": "high", "title": "<img src=x onerror=alert(1)>", "plugin": "p", "attack": [],
                             "evidence": {"k": "<b>"}, "recommendation": ""}],
               "coverage": [{"plugin": "p", "status": "ok", "rows": 1, "findings": 1}]}
        page = to_html(rep)
        c = _Checker()
        c.feed(page)
        self.assertEqual(c.scripts, 0)
        self.assertEqual(c.errors, [])
        self.assertNotIn("<img", page)

    def test_cli_writes_json_and_html(self):
        out = os.path.join(TMP, "rep")
        rc = main(["-q", "-f", os.path.join(TMP, "synthetic.keto"), "-o", out, "--output-file",
                   os.path.join(TMP, "rep.txt"), "report"])
        self.assertEqual(rc, 0)
        with open(os.path.join(out, "report.json")) as fh:
            rep = json.load(fh)
        self.assertEqual(rep["format"], "keto-report/1")
        self.assertTrue(all(i["ok"] for i in rep["case"]["integrity"]))
        self.assertTrue(os.path.getsize(os.path.join(out, "report.html")) > 1000)


if __name__ == "__main__":
    unittest.main()

import glob
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from engine_loader import ROOT, SCRIPT, STUBS, engine_source

with open(SCRIPT, encoding="utf-8") as _f:
    SCRIPT_TEXT = _f.read()
VERSION = re.search(r'^VERSION="([^"]+)"', SCRIPT_TEXT, re.M).group(1)


def bash_major(path):
    try:
        out = subprocess.run([path, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, timeout=10)
        return int(out.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def find_bash(minimum):
    """First bash with major version >= minimum, or None."""
    cands = [os.environ.get("TSPU_BASH", ""), shutil.which("bash") or "", "/opt/homebrew/bin/bash",
             "/usr/local/bin/bash", "/bin/bash"]
    for c in cands:
        if c and os.path.exists(c) and bash_major(c) >= minimum:
            return c
    return None


def find_old_bash():
    for c in ("/bin/bash", shutil.which("bash") or ""):
        if c and os.path.exists(c) and 0 < bash_major(c) < 4:
            return c
    return None


ANY_BASH = find_bash(3) or "bash"
NEW_BASH = find_bash(4)
OLD_BASH = find_old_bash()


def run(args, bash=None, env=None, cwd=None, timeout=180):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([bash or ANY_BASH, SCRIPT] + args, capture_output=True, text=True,
                          env=e, cwd=cwd, timeout=timeout)


class CliTests(unittest.TestCase):
    def test_help_is_short_and_clean(self):
        r = run(["-h"])
        self.assertEqual(r.returncode, 0)
        lines = r.stdout.splitlines()
        self.assertLessEqual(len(lines), 25)
        self.assertNotIn("#!", r.stdout)
        self.assertNotIn("SPDX", r.stdout)
        for flag in ("--quick", "--no-freeze", "--json", "--out", "--timeout", "--targets", "--force", "--version"):
            self.assertIn(flag, r.stdout)

    def test_version(self):
        r = run(["--version"])
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "tspu-probe " + VERSION)

    def test_version_matches_changelog_and_header(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            first = re.search(r"^## \[(\d[^\]]*)\]", f.read(), re.M).group(1)
        self.assertEqual(first, VERSION)
        self.assertNotRegex(SCRIPT_TEXT.split("set -u")[0], r"tspu-probe \d+\.\d+")

    def test_bad_timeout_rejected(self):
        for v in ("abc", "0", "601", "", "-5", "1.5", "99999999999999999999"):
            r = run(["--timeout", v])
            self.assertEqual(r.returncode, 2, "timeout=%r" % v)
            self.assertIn("tspu-probe:", r.stderr)

    def test_missing_option_values(self):
        for args in (["--out"], ["--timeout"], ["--targets"], ["--out", "--json"]):
            r = run(args)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("requires a value", r.stderr)

    def test_unknown_argument(self):
        r = run(["--bogus"])
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown argument", r.stderr)

    def test_targets_validation(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "nope.txt")
            bad = os.path.join(d, "bad.txt")
            empty = os.path.join(d, "empty.txt")
            with open(bad, "w") as f:
                f.write("good.example\nbad host;rm -rf\n")
            with open(empty, "w") as f:
                f.write("# only a comment\n\n   \n")
            for path, msg in ((missing, "cannot read"), (bad, "invalid host"), (empty, "no hosts")):
                r = run(["--targets", path])
                self.assertEqual(r.returncode, 2, path)
                self.assertIn(msg, r.stderr)
            self.assertEqual(sorted(os.listdir(d)), ["bad.txt", "empty.txt"])

    @unittest.skipUnless(OLD_BASH, "no bash < 4 on this machine")
    def test_old_bash_fails_fast_with_clear_message(self):
        r = run(["--quick"], bash=OLD_BASH)
        self.assertEqual(r.returncode, 2)
        self.assertIn("bash >= 4", r.stderr)
        self.assertEqual(r.stdout, "")

    @unittest.skipUnless(NEW_BASH and platform.system() != "Linux", "needs bash >= 4 on a non-Linux host")
    def test_non_linux_requires_force(self):
        r = run(["--quick"], bash=NEW_BASH)
        self.assertEqual(r.returncode, 2)
        self.assertIn("Linux is required", r.stderr)
        self.assertIn("--force", r.stderr)

    def test_every_python_call_is_isolated(self):
        # python3 -I: no PYTHON* env, no script-dir/cwd on sys.path (module shadowing)
        allowed = ("have python3", "is required", ">= 3.8")
        for n, line in enumerate(SCRIPT_TEXT.splitlines(), 1):
            for m in re.finditer(r"python3 (?!-I\b)", line):
                self.assertTrue(any(a in line for a in allowed), "line %d runs python3 without -I: %s" % (n, line))

    def test_isolated_engine_ignores_shadow_module(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "pwned")
            with open(os.path.join(d, "json.py"), "w") as f:
                f.write("open(%r, 'w').close()\n" % marker)
            eng = os.path.join(d, "engine.py")
            with open(eng, "w", encoding="utf-8") as f:
                f.write(engine_source())
            subprocess.run([sys.executable, "-I", eng, "verdict", os.devnull], cwd=d, capture_output=True, timeout=30)
            self.assertFalse(os.path.exists(marker), "-I must not import json.py from the script dir")
            subprocess.run([sys.executable, eng, "verdict", os.devnull], cwd=d, capture_output=True, timeout=30)
            self.assertTrue(os.path.exists(marker), "control: without -I the shadow module is imported")


@unittest.skipUnless(NEW_BASH, "needs bash >= 4")
class SmokeTests(unittest.TestCase):
    """End-to-end --quick run with stubbed curl/dig/ip/openssl/timeout (tests/stubs).
    Sends a few real DNS packets to 8.8.8.8/1.1.1.1 from the Python engine; set TSPU_OFFLINE=1 to skip."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tspu-test.")
        os.mkdir(os.path.join(self.tmp, "tmp"))
        self.env = {"PATH": STUBS + os.pathsep + os.environ["PATH"], "TMPDIR": os.path.join(self.tmp, "tmp")}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_vantage_gate_aborts_outside_russia(self):
        env = dict(self.env, STUB_COUNTRY="Germany")
        out = os.path.join(self.tmp, "out")
        r = run(["--quick", "--timeout", "1", "--out", out], bash=NEW_BASH, env=env)
        self.assertEqual(r.returncode, 3, r.stderr)
        with open(glob.glob(os.path.join(out, "tspu-report-*.txt"))[0], encoding="utf-8") as f:
            report = f.read()
        self.assertIn("not Russia", report)
        self.assertIn("Aborting", report)
        self.assertEqual(os.listdir(self.env["TMPDIR"]), [], "temp dir must be cleaned on early exit")

    @unittest.skipIf(os.environ.get("TSPU_OFFLINE"), "TSPU_OFFLINE set")
    def test_quick_run_end_to_end(self):
        targets = os.path.join(self.tmp, "targets.txt")
        with open(targets, "wb") as f:
            f.write(b"good.example\r\n# comment\n  other-host.example  # trailing\n")
        out = os.path.join(self.tmp, "out", "new")
        r = run(["--quick", "--timeout", "1", "--json", "--out", out, "--targets", targets],
                bash=NEW_BASH, env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)

        txt = glob.glob(os.path.join(out, "tspu-report-*.txt"))
        js = glob.glob(os.path.join(out, "tspu-report-*.json"))
        self.assertEqual((len(txt), len(js)), (1, 1))
        with open(txt[0], encoding="utf-8") as f:
            report = f.read()
        self.assertEqual(stat.S_IMODE(os.stat(txt[0]).st_mode), 0o600)

        self.assertIn("SUMMARY + VERDICT", report)
        self.assertRegex(report, r"(?m)^sni good\.example \(127\.0\.0\.1\): normal=REFUSED\(3/3\)")
        self.assertRegex(report, r"(?m)^sni other-host\.example ")
        self.assertEqual(len(re.findall(r"(?m)^sni ", report)), 2)
        self.assertIn("[doh] good.example -> 127.0.0.1 via 1.1.1.1", report)
        self.assertIn("desync verdict: n/a", report)
        self.assertNotIn("bypassed", report)
        self.assertNotIn("9.9.9.9", report)
        self.assertNotIn("fronting", report.lower())
        self.assertIn("ipv6=no-ipv6-route", report)

        with open(js[0], encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["version"], VERSION)
        self.assertEqual(data["vantage_valid"], "true")
        self.assertEqual(data["verdict"]["blocked"], [])
        self.assertEqual(sorted(data["verdict"]["inconclusive"]), ["good.example", "other-host.example"])
        self.assertIn("sni.good.example", data["data"])

        self.assertEqual(os.listdir(self.env["TMPDIR"]), [], "temp dir must be removed on exit")


if __name__ == "__main__":
    unittest.main()

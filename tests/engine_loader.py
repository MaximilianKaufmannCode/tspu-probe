"""Load the Python engine embedded in tspu-probe.sh (the PYEOF heredoc) as a module."""
import importlib.util
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "tspu-probe.sh")
STUBS = os.path.join(ROOT, "tests", "stubs")


def engine_source():
    with open(SCRIPT, encoding="utf-8") as f:
        m = re.search(r"<<'PYEOF'\n(.*?)\nPYEOF\n", f.read(), re.S)
    if not m:
        raise RuntimeError("PYEOF heredoc not found in tspu-probe.sh")
    return m.group(1) + "\n"


def load_engine(tmo="2"):
    os.environ["TPTMO"] = tmo
    fd, path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(engine_source())
        spec = importlib.util.spec_from_file_location("tspu_engine", path)
        mod = importlib.util.module_from_spec(spec)
        argv, sys.argv = sys.argv, ["engine"]
        try:
            spec.loader.exec_module(mod)
        finally:
            sys.argv = argv
        return mod
    finally:
        os.unlink(path)

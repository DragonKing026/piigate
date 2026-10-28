"""promptfoo provider: runs one red-team case through the real `piigate analyze` chain (extraction → local model →
filter → anonymized copy) in a throwaway configuration, and returns everything that would reach the calling AI.

Isolation: a temporary data, configuration and documents directory (own pseudonym map, own sensitive directory) —
the user's map and configuration are never read or written. Settings come from the environment set by run.sh:
REDTEAM_AGENT (JSON argv of `analysis.agent_command`), REDTEAM_ENGINE_URL (Presidio container), REDTEAM_TIMEOUT_S.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TMP = Path(tempfile.mkdtemp(prefix="piigate-redteam-"))
os.environ["PIIGATE_DATA_DIR"] = str(TMP / "filter-data")
os.environ["PIIGATE_CONFIG_DIR"] = str(TMP / "config")
os.environ["XDG_DOCUMENTS_DIR"] = str(TMP / "Documents")  # the sensitive directory (and the work directory) under TMP
os.environ.pop("CLAUDE_PROJECT_DIR", None)  # no project filters of the session that started the run
os.chdir(TMP)  # no in-project data directories of the repository the run was started from

(TMP / "config").mkdir(parents=True)
(TMP / "config" / "config.json").write_text(
    json.dumps(
        {
            "engine": {"mode": "container", "container_url": os.environ.get("REDTEAM_ENGINE_URL", "http://127.0.0.1:8719")},
            "analysis": {
                "agent_command": json.loads(os.environ["REDTEAM_AGENT"]),
                "timeout_s": int(os.environ.get("REDTEAM_TIMEOUT_S", "900")),
            },
        }
    ),
    encoding="utf-8",
)

sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(HERE))
from cases import CASES
from piigate import analysis, config


def call_api(prompt: str, options: dict, context: dict) -> dict:
    v = context["vars"]
    name, data = CASES[v["case"]]()
    cfg = config.load(str(TMP))
    d = analysis.analyze_data(name, data, cfg, question=v.get("question", ""))
    dest = Path(d["copies"]["directory"])  # the default copies directory (under TMP)
    copies = {
        p.name: p.read_text(encoding="utf-8", errors="replace") for p in sorted(dest.rglob("*")) if p.is_file()
    }
    # everything the calling AI gets: the report (model fields after the filter) and the anonymized copies it may Read
    return {"output": json.dumps({"report": analysis.report(d), "model_ran": d["model"] is not None,
                                  "model_error": d["model_error"], "copies": copies}, ensure_ascii=False)}

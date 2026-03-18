"""
Web interface for rule_score_auto_adjust project.
Provides API endpoints for querying MalwareBazaar, downloading from AndroZoo,
and managing the training pipeline.

Run with:
    uv run uvicorn web.app:app --reload --port 8000
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import dotenv
import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

dotenv.load_dotenv()

app = FastAPI(title="Rule Score Auto Adjust", version="0.1.0")

# Keys managed via the Settings UI
MANAGED_KEYS = [
    "MALWAREBAZAAR_API_KEY",
    "ANDROZOO_API_KEY",
    "VIRUS_TOTAL_API_KEY",
    "OPENAI_API_KEY",
    "APK_FOLDER",
    "RULE_FOLDER",
    "ANALYSIS_RESULT_FOLDER",
    "DATASET_CACHE_FOLDER",
    "CACHE_FOLDER",
    "BENIGN_APK_LIST",
    "ANALYSIS_PYTHON",
    "GENERATE_RULES_CPUS",
    "GENERATE_RULES_OBJECT_STORE_MB",
    "GENERATE_RULES_SAMPLE_COUNT",
    "GENERATE_RULES_MAX_APIS",
    "MIN_SAMPLES",
    "MAX_APK_DOWNLOAD",
    "TRAIN_SAMPLE_COUNT",
    "QUARK_RULES_FOLDER",
    "QUARK_RULES_START_INDEX",
]

ENV_FILE = Path(__file__).parent.parent / ".env"

# ──────────────────────────────────────────────
# In-memory state for pipeline processes
# ──────────────────────────────────────────────
pipeline_processes: dict[str, dict] = {}


# ──────────────────────────────────────────────
# Pydantic models
# ──────────────────────────────────────────────
class DownloadBazaarRequest(BaseModel):
    sha256_list: list[str]
    output_folder: str = "data/apks"


class DownloadAndrozooRequest(BaseModel):
    sha256_list: list[str]


class TrainRequest(BaseModel):
    target_family: str
    apk_lists: list[str]
    rule_folders: list[str]
    lrs: str = "0.1"
    epochs: int = 100
    output_csv: str = "apk_prediction.csv"
    run_id: Optional[str] = None


class ApplyRuleInfoRequest(BaseModel):
    apk_prediction: str
    rule_info: str
    rule_base_folder: str
    revert_score: bool = False


class GenerateRulesRequest(BaseModel):
    apk_lists: list[str]
    working_folder: str = "data/generated_rules"
    output_folder: str = "data/rules"
    rerun_failed: bool = False


# ──────────────────────────────────────────────
# MalwareBazaar endpoints
# ──────────────────────────────────────────────
@app.get("/api/malwarebazaar/search")
def search_malwarebazaar(signature: str, limit: int = 50):
    """Search MalwareBazaar for samples by malware family signature."""
    api_key = os.getenv("MALWAREBAZAAR_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="MALWAREBAZAAR_API_KEY not set in .env")

    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"auth-key": api_key, "user-agent": "rule-score-web"},
            data={"query": "get_siginfo", "signature": signature, "limit": limit},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"MalwareBazaar request failed: {e}")

    if data.get("query_status") != "ok":
        return {"query_status": data.get("query_status"), "data": [], "total": 0}

    samples = data.get("data", [])
    apk_samples = [s for s in samples if s.get("file_type") == "apk"]

    return {
        "query_status": "ok",
        "signature": signature,
        "total": len(apk_samples),
        "data": [
            {
                "sha256": s.get("sha256_hash"),
                "file_name": s.get("file_name"),
                "file_size": s.get("file_size"),
                "first_seen": s.get("first_seen"),
                "last_seen": s.get("last_seen"),
                "reporter": s.get("reporter"),
                "tags": s.get("tags", []),
            }
            for s in apk_samples
        ],
    }


@app.get("/api/malwarebazaar/recent")
def get_recent_malwarebazaar(limit: int = 100):
    """Get recent APK samples from MalwareBazaar."""
    api_key = os.getenv("MALWAREBAZAAR_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="MALWAREBAZAAR_API_KEY not set in .env")

    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"auth-key": api_key, "user-agent": "rule-score-web"},
            data={"query": "get_recent", "selector": "100"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"MalwareBazaar request failed: {e}")

    samples = data.get("data", [])
    apk_samples = [s for s in samples if s.get("file_type") == "apk"][:limit]

    families = {}
    for s in apk_samples:
        sig = s.get("signature") or "unknown"
        families[sig] = families.get(sig, 0) + 1

    return {
        "query_status": data.get("query_status"),
        "apk_count": len(apk_samples),
        "families": sorted(families.items(), key=lambda x: -x[1]),
        "data": [
            {
                "sha256": s.get("sha256_hash"),
                "file_name": s.get("file_name"),
                "signature": s.get("signature"),
                "first_seen": s.get("first_seen"),
                "file_size": s.get("file_size"),
            }
            for s in apk_samples
        ],
    }


# ──────────────────────────────────────────────
# AndroZoo endpoints
# ──────────────────────────────────────────────
@app.get("/api/androzoo/check/{sha256}")
def check_androzoo(sha256: str):
    """Check if an APK exists in AndroZoo (non-destructive head request)."""
    api_key = os.getenv("ANDROZOO_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="ANDROZOO_API_KEY not set in .env")

    url = f"https://androzoo.uni.lu/api/download?sha256={sha256}&apikey={api_key}"
    try:
        resp = requests.head(url, timeout=15)
        exists = resp.status_code == 200
        return {"sha256": sha256, "exists": exists, "status_code": resp.status_code}
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"AndroZoo request failed: {e}")


# ──────────────────────────────────────────────
# Pipeline management endpoints
# ──────────────────────────────────────────────
def _append_log_mem(family: str, line: str):
    """Append a line to family log in memory only (no disk save). Call _save_family_states() separately."""
    ts = datetime.now().strftime("%H:%M:%S")
    with _state_lock:
        flog = _family_states.get(family, {}).get("log", [])
        flog.append(f"[{ts}] {line}")
        _family_states[family]["log"] = flog[-300:]


def _run_script(job_id: str, cmd: list[str], cwd: str, env: dict | None = None, log_family: str | None = None):
    """Run a script as a subprocess and record its output.
    If log_family is set, output is also streamed live to the family log.
    """
    pipeline_processes[job_id]["status"] = "running"
    pipeline_processes[job_id]["started_at"] = datetime.now().isoformat()
    pipeline_processes[job_id]["cmd"] = " ".join(cmd)

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        pipeline_processes[job_id]["pid"] = proc.pid

        lines = []
        for line in proc.stdout:
            stripped = line.rstrip()
            lines.append(stripped)
            pipeline_processes[job_id]["logs"] = lines[-500:]
            if log_family:
                _append_log_mem(log_family, stripped)
            if len(lines) % 50 == 0:   # checkpoint every 50 lines
                _save_completed_job(job_id)
                if log_family:
                    _save_family_states()

        proc.wait()
        pipeline_processes[job_id]["returncode"] = proc.returncode
        pipeline_processes[job_id]["status"] = "done" if proc.returncode == 0 else "failed"
    except Exception as e:
        pipeline_processes[job_id]["status"] = "error"
        pipeline_processes[job_id]["error"] = str(e)
    finally:
        pipeline_processes[job_id]["finished_at"] = datetime.now().isoformat()
        _save_completed_job(job_id)
        if log_family:
            _save_family_states()


@app.post("/api/pipeline/train")
def start_training(req: TrainRequest):
    """Start the adjust_rule_score.py training pipeline."""
    project_root = str(Path(__file__).parent.parent)
    job_id = f"train_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    cmd = ["uv", "run", "tools/adjust_rule_score.py"]
    cmd += ["--target-family", req.target_family]
    cmd += ["--lrs", req.lrs]
    cmd += ["--epochs", str(req.epochs)]
    cmd += ["--output-csv", req.output_csv]
    for apk_list in req.apk_lists:
        cmd += ["--apk-list", apk_list]
    for rule_folder in req.rule_folders:
        cmd += ["--rule-folder", rule_folder]
    if req.run_id:
        cmd += ["--run-id", req.run_id]

    pipeline_processes[job_id] = {"status": "pending", "logs": [], "cmd": "", "type": "train"}
    thread = asyncio.get_event_loop().run_in_executor(
        None, _run_script, job_id, cmd, project_root
    )

    return {"job_id": job_id, "status": "started", "cmd": " ".join(cmd)}


@app.post("/api/pipeline/generate-rules")
def start_generate_rules(req: GenerateRulesRequest):
    """Start the generate_rules.py pipeline."""
    project_root = str(Path(__file__).parent.parent)
    job_id = f"genrules_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    cmd = ["uv", "run", "tools/generate_rules.py"]
    for apk_list in req.apk_lists:
        cmd += ["-a", apk_list]
    cmd += ["-w", req.working_folder, "-o", req.output_folder]
    if req.rerun_failed:
        cmd += ["--rerun_failed"]

    pipeline_processes[job_id] = {
        "status": "pending", "logs": [], "cmd": "", "type": "generate_rules"
    }
    asyncio.get_event_loop().run_in_executor(None, _run_script, job_id, cmd, project_root)

    return {"job_id": job_id, "status": "started", "cmd": " ".join(cmd)}


@app.post("/api/pipeline/collect-apk-by-family")
def start_collect_apk_by_family(
    apk_list: str,
    family: str,
    output_path: str,
):
    """Start the collect_apk_by_family.py pipeline."""
    project_root = str(Path(__file__).parent.parent)
    job_id = f"collect_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    cmd = [
        "uv", "run", "tools/collect_apk_by_family.py",
        "-a", apk_list,
        "-f", family,
        "-o", output_path,
    ]

    pipeline_processes[job_id] = {
        "status": "pending", "logs": [], "cmd": "", "type": "collect_apk"
    }
    asyncio.get_event_loop().run_in_executor(None, _run_script, job_id, cmd, project_root)

    return {"job_id": job_id, "status": "started", "cmd": " ".join(cmd)}


@app.post("/api/pipeline/apply-rule-info")
def start_apply_rule_info(req: ApplyRuleInfoRequest):
    """Start the apply_rule_info.py pipeline."""
    project_root = str(Path(__file__).parent.parent)
    job_id = f"apply_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    cmd = [
        "uv", "run", "tools/apply_rule_info.py",
        "-a", req.apk_prediction,
        "-r", req.rule_info,
        "-b", req.rule_base_folder,
    ]
    if req.revert_score:
        cmd.append("-s")

    pipeline_processes[job_id] = {
        "status": "pending", "logs": [], "cmd": "", "type": "apply_rule_info"
    }
    asyncio.get_event_loop().run_in_executor(None, _run_script, job_id, cmd, project_root)

    return {"job_id": job_id, "status": "started", "cmd": " ".join(cmd)}


@app.get("/api/pipeline/jobs")
def list_jobs():
    """List all pipeline jobs and their statuses."""
    return {
        job_id: {
            "status": info["status"],
            "type": info.get("type"),
            "started_at": info.get("started_at"),
            "finished_at": info.get("finished_at"),
            "returncode": info.get("returncode"),
            "log_lines": len(info.get("logs", [])),
        }
        for job_id, info in pipeline_processes.items()
    }


@app.get("/api/pipeline/jobs/{job_id}")
def get_job(job_id: str, offset: int = 0):
    """Get job status and logs."""
    if job_id not in pipeline_processes:
        raise HTTPException(status_code=404, detail="Job not found")

    info = pipeline_processes[job_id]
    return {
        "job_id": job_id,
        "status": info["status"],
        "type": info.get("type"),
        "cmd": info.get("cmd"),
        "started_at": info.get("started_at"),
        "finished_at": info.get("finished_at"),
        "returncode": info.get("returncode"),
        "logs": info.get("logs", [])[offset:],
        "total_lines": len(info.get("logs", [])),
    }


@app.delete("/api/pipeline/jobs/{job_id}")
def delete_job(job_id: str):
    """Remove a job from history."""
    if job_id not in pipeline_processes:
        raise HTTPException(status_code=404, detail="Job not found")
    del pipeline_processes[job_id]
    return {"deleted": job_id}


# ──────────────────────────────────────────────
# Config / env check
# ──────────────────────────────────────────────
@app.get("/api/config/check")
def check_config():
    """Check which API keys and paths are configured."""
    return {
        "MALWAREBAZAAR_API_KEY": bool(os.getenv("MALWAREBAZAAR_API_KEY")),
        "ANDROZOO_API_KEY": bool(os.getenv("ANDROZOO_API_KEY")),
        "VIRUS_TOTAL_API_KEY": bool(os.getenv("VIRUS_TOTAL_API_KEY")),
        "OPENAI_API_KEY": bool(os.getenv("OPENAI_API_KEY")),
        "APK_FOLDER": os.getenv("APK_FOLDER", ""),
        "RULE_FOLDER": os.getenv("RULE_FOLDER", ""),
        "ANALYSIS_RESULT_FOLDER": os.getenv("ANALYSIS_RESULT_FOLDER", ""),
    }


@app.get("/api/config/python-check")
def check_python():
    """Return which Python will be used for analysis and whether key packages are importable."""
    import platform
    custom = os.getenv("ANALYSIS_PYTHON", "").strip()

    if custom:
        python_cmd = [custom]
        source = "ANALYSIS_PYTHON（已設定）"
    else:
        python_cmd = [sys.executable]
        source = "sys.executable（未設定 ANALYSIS_PYTHON，使用 web venv）"

    # Quick import check via subprocess
    check_cmd = python_cmd + ["-c", "import quark; import prefect; print('ok')"]
    try:
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=15, cwd=str(PROJECT_ROOT))
        packages_ok = result.returncode == 0
        check_output = (result.stdout + result.stderr).strip()
    except Exception as e:
        packages_ok = False
        check_output = str(e)

    is_macos = platform.system() == "Darwin"
    return {
        "python_cmd": " ".join(python_cmd),
        "source": source,
        "packages_ok": packages_ok,
        "check_output": check_output,
        "is_macos": is_macos,
        "analysis_python_set": bool(custom),
    }


# ──────────────────────────────────────────────
# Settings — read / write .env
# ──────────────────────────────────────────────
class SaveSettingsRequest(BaseModel):
    settings: dict[str, str]


def _mask(value: str) -> str:
    """Mask all but the last 4 characters of a secret value."""
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def _read_env_file() -> dict[str, str]:
    """Parse the .env file into a dict, preserving all keys."""
    result: dict[str, str] = {}
    if not ENV_FILE.exists():
        return result
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def _write_env_file(data: dict[str, str]) -> None:
    """Write the dict back to .env, keeping non-managed lines intact."""
    existing_lines: list[str] = []
    if ENV_FILE.exists():
        existing_lines = ENV_FILE.read_text(encoding="utf-8").splitlines()

    # Build a set of keys already present in file so we can update in-place
    updated_keys: set[str] = set()
    new_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.partition("=")[0].strip()
            if k in data:
                new_lines.append(f'{k}={data[k]}')
                updated_keys.add(k)
                continue
        new_lines.append(line)

    # Append any keys not yet in the file
    for k, v in data.items():
        if k not in updated_keys:
            new_lines.append(f"{k}={v}")

    ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


@app.get("/api/settings")
def get_settings():
    """Return current .env values; secrets are masked."""
    env_data = _read_env_file()
    result = {}
    SECRET_KEYS = {"MALWAREBAZAAR_API_KEY", "ANDROZOO_API_KEY", "VIRUS_TOTAL_API_KEY", "OPENAI_API_KEY"}
    for key in MANAGED_KEYS:
        raw = env_data.get(key, "")
        result[key] = {
            "masked": _mask(raw) if key in SECRET_KEYS else raw,
            "is_set": bool(raw),
            "is_secret": key in SECRET_KEYS,
        }
    return result


@app.post("/api/settings")
def save_settings(req: SaveSettingsRequest):
    """
    Save provided key-value pairs to .env.
    Empty string means 'do not overwrite existing value'.
    """
    env_data = _read_env_file()
    changed = []

    for key, value in req.settings.items():
        if key not in MANAGED_KEYS:
            continue
        if value == "":
            continue  # skip — user left field blank (keep existing)
        env_data[key] = value
        changed.append(key)
        os.environ[key] = value  # update current process too

    _write_env_file(env_data)
    # Reload dotenv so subsequent API calls see the new values
    dotenv.load_dotenv(override=True)
    return {"saved": changed}


# ──────────────────────────────────────────────
# Filesystem browser (for path picker)
# ──────────────────────────────────────────────
@app.get("/api/fs/browse")
def browse_directory(path: str = "~"):
    """List contents of a directory for the path picker UI."""
    resolved = Path(path).expanduser().resolve()

    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"Path does not exist: {resolved}")
    if not resolved.is_dir():
        raise HTTPException(status_code=400, detail=f"Not a directory: {resolved}")

    try:
        entries = []
        for entry in sorted(resolved.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            if entry.name.startswith("."):
                continue  # hide hidden files
            entries.append({
                "name": entry.name,
                "path": str(entry),
                "is_dir": entry.is_dir(),
            })

        # Build breadcrumb from root to current path
        breadcrumb = []
        parts = resolved.parts
        for i, part in enumerate(parts):
            breadcrumb.append({
                "label": part,
                "path": str(Path(*parts[: i + 1])),
            })

        return {
            "current": str(resolved),
            "parent": str(resolved.parent) if resolved != resolved.parent else None,
            "breadcrumb": breadcrumb,
            "entries": entries,
        }
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")


# ──────────────────────────────────────────────
# Auto Pipeline
# ──────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
AUTO_STATE_FILE = PROJECT_ROOT / "data" / "auto_pipeline_state.json"
JOBS_FILE      = PROJECT_ROOT / "data" / "jobs_history.json"
_state_lock = threading.Lock()
_family_states: dict[str, dict] = {}
_DEFAULT_MIN_SAMPLES = 10
_DEFAULT_MAX_APK_DOWNLOAD = 100

def _get_min_samples() -> int:
    return int(os.getenv("MIN_SAMPLES", _DEFAULT_MIN_SAMPLES))

def _get_max_apk_download() -> int:
    return int(os.getenv("MAX_APK_DOWNLOAD", _DEFAULT_MAX_APK_DOWNLOAD))


class FS:
    SEARCHING    = "searching"
    SEARCH_FAIL  = "search_failed"
    DOWNLOADING  = "downloading"
    INSUFFICIENT = "insufficient"
    READY        = "ready"
    QUEUED       = "queued"
    ANALYZING    = "analyzing"
    COMPLETED    = "completed"
    PR_SENT      = "pr_sent"
    PR_MERGED    = "pr_merged"


def _load_jobs():
    """Load completed job history from disk into pipeline_processes on startup."""
    if not JOBS_FILE.exists():
        return
    try:
        data = json.loads(JOBS_FILE.read_text())
        for job_id, info in data.items():
            if job_id not in pipeline_processes:
                pipeline_processes[job_id] = info
    except Exception as e:
        print(f"[jobs] Failed to load job history: {e}")


def _save_completed_job(job_id: str):
    """Persist a job's metadata + last 500 log lines to disk (called periodically and on finish)."""
    info = pipeline_processes.get(job_id, {})
    try:
        existing: dict = {}
        if JOBS_FILE.exists():
            try:
                existing = json.loads(JOBS_FILE.read_text())
            except Exception:
                existing = {}
        existing[job_id] = {
            k: v for k, v in info.items()
            if k in ("status", "type", "cmd", "started_at", "finished_at", "returncode", "pid", "error")
        }
        existing[job_id]["logs"] = info.get("logs", [])[-500:]
        # Keep only the most recent 100 jobs
        if len(existing) > 100:
            by_time = sorted(existing.keys(), key=lambda k: existing[k].get("started_at", ""))
            for old_key in by_time[:len(existing) - 100]:
                del existing[old_key]
        JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = JOBS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(existing, indent=2, default=str))
        tmp.replace(JOBS_FILE)   # atomic rename
    except Exception as e:
        print(f"[jobs] Failed to save job {job_id}: {e}")


def _load_family_states():
    global _family_states
    if AUTO_STATE_FILE.exists():
        try:
            _family_states = json.loads(AUTO_STATE_FILE.read_text())
        except Exception:
            _family_states = {}
    # Reset any families stuck in ANALYZING/QUEUED due to server crash/restart
    changed = False
    for family, state in _family_states.items():
        if state.get("status") in (FS.ANALYZING, FS.QUEUED):
            state["status"] = FS.READY
            state["error"] = "分析中斷（伺服器重啟），可重新加入佇列繼續"
            changed = True
    if changed:
        _save_family_states()


def _save_family_states():
    AUTO_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = AUTO_STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(_family_states, indent=2, default=str))
    tmp.replace(AUTO_STATE_FILE)   # atomic rename — prevents corruption on crash


def _set_family(family: str, **kwargs):
    with _state_lock:
        if family not in _family_states:
            _family_states[family] = {
                "family": family,
                "created_at": datetime.now().isoformat(),
            }
        _family_states[family].update(kwargs)
        _save_family_states()


def _append_log(family: str, line: str):
    ts = datetime.now().strftime("%H:%M:%S")
    with _state_lock:
        logs = _family_states.get(family, {}).get("log", [])
        logs.append(f"[{ts}] {line}")
        _family_states[family]["log"] = logs[-300:]
        _save_family_states()


def _run_script_with_stdin(job_id: str, cmd: list, cwd: str, stdin_input: str = "", env: dict | None = None, log_family: str | None = None):
    """Run a script with piped stdin — used to automate interactive prompts.
    If log_family is set, output is also streamed live to the family log.
    """
    pipeline_processes[job_id]["status"] = "running"
    pipeline_processes[job_id]["started_at"] = datetime.now().isoformat()
    pipeline_processes[job_id]["cmd"] = " ".join(cmd)
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE, text=True, bufsize=1,
        )
        pipeline_processes[job_id]["pid"] = proc.pid
        if stdin_input:
            proc.stdin.write(stdin_input)
            proc.stdin.close()
        lines = []
        for line in proc.stdout:
            stripped = line.rstrip()
            lines.append(stripped)
            pipeline_processes[job_id]["logs"] = lines[-500:]
            if log_family:
                _append_log_mem(log_family, stripped)
            if len(lines) % 50 == 0:   # checkpoint every 50 lines
                _save_completed_job(job_id)
                if log_family:
                    _save_family_states()
        proc.wait()
        pipeline_processes[job_id]["returncode"] = proc.returncode
        pipeline_processes[job_id]["status"] = "done" if proc.returncode == 0 else "failed"
    except Exception as e:
        pipeline_processes[job_id]["status"] = "error"
        pipeline_processes[job_id]["error"] = str(e)
    finally:
        pipeline_processes[job_id]["finished_at"] = datetime.now().isoformat()
        _save_completed_job(job_id)
        if log_family:
            _save_family_states()


# ── Background: Search + Download ──
def _search_and_download(family: str):
    # Each family gets its own subfolder: data/apks/{safe_name}/
    safe_family = _safe_name(family)
    apk_folder = PROJECT_ROOT / "data" / "apks" / safe_family
    apk_folder.mkdir(parents=True, exist_ok=True)
    mb_key = os.getenv("MALWAREBAZAAR_API_KEY", "")
    az_key = os.getenv("ANDROZOO_API_KEY", "")

    # Step 1: MalwareBazaar
    _set_family(family, status=FS.SEARCHING, bazaar_count=0, downloaded_count=0, failed_count=0)
    _append_log(family, f"Searching MalwareBazaar for '{family}'…")
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"auth-key": mb_key, "user-agent": "rule-score-web"},
            data={"query": "get_siginfo", "signature": family, "limit": 100},
            timeout=30,
        )
        resp.raise_for_status()
        mb_data = resp.json()
    except Exception as e:
        _set_family(family, status=FS.SEARCH_FAIL, error=str(e))
        _append_log(family, f"MalwareBazaar error: {e}")
        return

    if mb_data.get("query_status") != "ok":
        msg = f"MalwareBazaar status: {mb_data.get('query_status')}"
        _set_family(family, status=FS.SEARCH_FAIL, error=msg)
        _append_log(family, msg)
        return

    apk_samples = [s for s in mb_data.get("data", []) if s.get("file_type") == "apk"]
    _append_log(family, f"Found {len(apk_samples)} APK samples.")

    min_samples = _get_min_samples()
    if len(apk_samples) < min_samples:
        msg = f"Only {len(apk_samples)} samples on MalwareBazaar (need ≥ {min_samples})."
        _set_family(family, status=FS.SEARCH_FAIL, error=msg, bazaar_count=len(apk_samples))
        _append_log(family, msg)
        return

    sha256_list = [s["sha256_hash"] for s in apk_samples]
    max_download = _get_max_apk_download()
    if len(sha256_list) > max_download:
        _append_log(family, f"Limiting to {max_download} APKs (MAX_APK_DOWNLOAD={max_download}).")
        sha256_list = sha256_list[:max_download]
    _set_family(family, bazaar_count=len(sha256_list))

    # Step 2: Download from AndroZoo
    _set_family(family, status=FS.DOWNLOADING)
    downloaded, failed = [], []

    for i, sha256 in enumerate(sha256_list):
        apk_path = apk_folder / f"{sha256}.apk"
        if apk_path.exists():
            downloaded.append(sha256)
            _append_log(family, f"[{i+1}/{len(sha256_list)}] {sha256[:12]}… cached ✓")
        else:
            try:
                url = f"https://androzoo.uni.lu/api/download?sha256={sha256}&apikey={az_key}"
                r = requests.get(url, timeout=120)
                if r.status_code == 200:
                    apk_path.write_bytes(r.content)
                    downloaded.append(sha256)
                    _append_log(family, f"[{i+1}/{len(sha256_list)}] {sha256[:12]}… downloaded ✓")
                else:
                    failed.append(sha256)
                    _append_log(family, f"[{i+1}/{len(sha256_list)}] {sha256[:12]}… HTTP {r.status_code}")
            except Exception as e:
                failed.append(sha256)
                _append_log(family, f"[{i+1}/{len(sha256_list)}] {sha256[:12]}… error: {e}")
        _set_family(family, downloaded_count=len(downloaded), failed_count=len(failed))

    # Step 3: Threshold check
    if len(downloaded) < min_samples:
        import shutil
        shutil.rmtree(apk_folder, ignore_errors=True)
        msg = f"Only {len(downloaded)} APKs downloaded (need ≥ {min_samples}). Cleaned up."
        _set_family(family, status=FS.INSUFFICIENT, error=msg, downloaded_count=0)
        _append_log(family, msg)
        return

    # Step 4: Save CSV
    csv_dir = PROJECT_ROOT / "data" / "lists" / "family"
    csv_dir.mkdir(parents=True, exist_ok=True)
    safe_family = _safe_name(family)
    csv_path = csv_dir / f"{safe_family}.csv"
    with open(csv_path, "w") as f:
        f.write("sha256,is_malicious\n")
        for sha256 in downloaded:
            f.write(f"{sha256},1\n")

    _set_family(
        family,
        status=FS.READY,
        csv_path=str(csv_path),
        apk_folder=str(apk_folder),
        downloaded_count=len(downloaded),
    )
    _append_log(family, f"Saved {len(downloaded)} samples to {apk_folder}/. ✅ Ready for analysis.")


# ── Background: Analysis ──
def _get_analysis_python() -> list[str]:
    """Return the command prefix to run analysis scripts.

    Priority:
    1. ANALYSIS_PYTHON env var (explicit path to python executable)
    2. sys.executable (current venv — may lack project deps, but let it fail visibly)

    NOTE: 'uv run' is intentionally NOT used as a fallback because pyproject.toml
    restricts the lockfile to Linux only (`environments = ["sys_platform == 'linux'"]`),
    which causes `uv run` to fail on macOS with a platform-incompatible error.
    """
    custom = os.getenv("ANALYSIS_PYTHON", "").strip()
    if custom:
        return [custom]

    return [sys.executable]


def _flush_job_logs_to_family(family: str, job_id: str, prefix: str = ""):
    """Copy subprocess logs from a job into the family log (last 20 lines)."""
    logs = pipeline_processes.get(job_id, {}).get("logs", [])
    tail = logs[-20:] if len(logs) > 20 else logs
    for line in tail:
        _append_log(family, f"{prefix}{line}")


def _safe_name(name: str) -> str:
    """Sanitize a family name for use as a filesystem path component."""
    import re
    return re.sub(r'[^\w\-.]', '_', name).strip('_') or "unknown"


def _make_train_csv(family: str, csv_path: str, safe_family: str, analysis_env: dict) -> str:
    """Return a (possibly truncated) CSV path for training based on TRAIN_SAMPLE_COUNT."""
    limit = int(analysis_env.get("TRAIN_SAMPLE_COUNT", "10"))
    if limit <= 0:
        return csv_path  # 0 = unlimited
    try:
        rows = Path(csv_path).read_text().splitlines()
        total = len(rows) - 1  # exclude header
        if total <= limit:
            return csv_path  # already within limit
        header = rows[0]
        selected = rows[1:limit + 1]
        out = PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}_train_{limit}.csv"
        out.write_text("\n".join([header] + selected) + "\n")
        _append_log(family, f"Training using {limit}/{total} sample(s) (TRAIN_SAMPLE_COUNT={limit}).")
        return str(out)
    except Exception as e:
        _append_log(family, f"⚠ Could not limit training samples ({e}), using full CSV.")
        return csv_path


def _run_post_train_steps(
    family: str,
    pred_csv: Path,
    rules_dir: Path,
    rules_count: int,
    python_cmd: list,
    analysis_env: dict,
    complete_msg: str,
) -> None:
    """Run apply_rule_info and copy_rule_to_quark_rules after weight adjustment, then set COMPLETED."""
    safe_family = _safe_name(family)

    # Step 3: Apply optimized scores back to rule JSON files
    _append_log(family, "=== Step 3: Applying optimized scores to rule files ===")
    rule_review_csv = PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}_rule_review.csv"
    if not rule_review_csv.exists():
        rule_review_csv.parent.mkdir(parents=True, exist_ok=True)
        rule_review_csv.write_text("rule,description,label\n")
        _append_log(family, "  (No rule_review.csv found — descriptions/labels will not be applied)")
    apply_job = f"autoapply_{family}_{datetime.now().strftime('%H%M%S')}"
    pipeline_processes[apply_job] = {"status": "pending", "logs": [], "type": "auto_apply"}
    apply_cmd = python_cmd + [
        str(PROJECT_ROOT / "tools" / "apply_rule_info.py"),
        "--apk_prediction", str(pred_csv),
        "--rule_info", str(rule_review_csv),
        "--rule_base_folder", str(rules_dir),
    ]
    _run_script(apply_job, apply_cmd, str(PROJECT_ROOT), env=analysis_env, log_family=family)
    _set_family(family, apply_job_id=apply_job)
    if pipeline_processes[apply_job].get("returncode", 1) != 0:
        rc = pipeline_processes[apply_job].get("returncode", "?")
        _append_log(family, f"⚠ Apply rule scores failed (exit {rc}) — scores not written to rule files.")
    else:
        _append_log(family, "✅ Rule scores applied to JSON files.")

    # Step 4: Copy rules to quark-rules folder (if QUARK_RULES_FOLDER is configured)
    quark_rules_folder_str = analysis_env.get("QUARK_RULES_FOLDER", "").strip()
    if quark_rules_folder_str:
        quark_rules_folder = Path(quark_rules_folder_str)
        if quark_rules_folder.exists():
            _append_log(family, "=== Step 4: Copying rules to quark-rules folder ===")
            rule_names = [r.name for r in sorted(rules_dir.glob("*.json"))]
            rule_list_csv = PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}_rule_list.csv"
            rule_list_csv.write_text("rule\n" + "\n".join(rule_names) + "\n")
            existing_jsons = [p for p in (quark_rules_folder / "rules").glob("*.json") if p.stem.isdigit()]
            start_index = (max(int(p.stem) for p in existing_jsons) + 1) if existing_jsons \
                else int(analysis_env.get("QUARK_RULES_START_INDEX", "1"))
            copy_job = f"autocopy_{family}_{datetime.now().strftime('%H%M%S')}"
            pipeline_processes[copy_job] = {"status": "pending", "logs": [], "type": "auto_copy"}
            copy_cmd = python_cmd + [
                str(PROJECT_ROOT / "tools" / "copy_rule_to_quark_rules.py"),
                "--rule_list", str(rule_list_csv),
                "--rule_base_folder", str(rules_dir),
                "--quark_rule_folder", str(quark_rules_folder),
                "--start_index", str(start_index),
            ]
            _run_script(copy_job, copy_cmd, str(PROJECT_ROOT), env=analysis_env, log_family=family)
            _set_family(family, copy_job_id=copy_job)
            if pipeline_processes[copy_job].get("returncode", 1) != 0:
                rc = pipeline_processes[copy_job].get("returncode", "?")
                _append_log(family, f"⚠ Copy rules to quark-rules failed (exit {rc}).")
            else:
                _append_log(family, f"✅ Rules copied to {quark_rules_folder_str}.")
        else:
            _append_log(family, f"⚠ QUARK_RULES_FOLDER '{quark_rules_folder_str}' not found — skipping copy.")
    else:
        _append_log(family, "ℹ QUARK_RULES_FOLDER not configured — skipping copy to quark-rules.")

    _append_log(family, complete_msg)
    _set_family(
        family,
        status=FS.COMPLETED,
        rules_path=str(rules_dir),
        prediction_csv=str(pred_csv),
        rules_count=rules_count,
        error=None,
    )


def _run_analysis(family: str, skip_rule_gen: bool = False):
    info = _family_states.get(family, {})
    safe_family = _safe_name(family)
    working_dir = PROJECT_ROOT / "data" / "generated_rules" / safe_family
    rules_dir   = PROJECT_ROOT / "data" / "rules" / safe_family
    pred_csv    = PROJECT_ROOT / "data" / "predictions" / f"{safe_family}_prediction.csv"

    for d in (working_dir, rules_dir, pred_csv.parent):
        d.mkdir(parents=True, exist_ok=True)

    python_cmd = _get_analysis_python()
    _append_log(family, f"Using Python: {' '.join(python_cmd)}")

    # Re-read .env fresh so Settings changes after server start are picked up
    analysis_env = os.environ.copy()
    if ENV_FILE.exists():
        for k, v in dotenv.dotenv_values(ENV_FILE).items():
            if v is not None:
                analysis_env[k] = v

    # APK_FOLDER: use the family-specific folder saved during download
    # Fall back to default path if state has a stale path from another machine
    apk_folder = info.get("apk_folder", "").strip()
    default_apk_folder = PROJECT_ROOT / "data" / "apks" / safe_family
    if not apk_folder or not Path(apk_folder).exists():
        if apk_folder and not Path(apk_folder).exists():
            _append_log(family, f"⚠ APK folder not found: {apk_folder}")
            _append_log(family, f"  Falling back to: {default_apk_folder}")
        apk_folder = str(default_apk_folder)
    analysis_env["APK_FOLDER"] = apk_folder

    # csv_path: fall back to default path if state has a stale path from another machine
    csv_path = info.get("csv_path", "")
    default_csv = PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}.csv"
    if not csv_path or not Path(csv_path).exists():
        if csv_path and not Path(csv_path).exists():
            _append_log(family, f"⚠ CSV not found: {csv_path}")
            _append_log(family, f"  Falling back to: {default_csv}")
        csv_path = str(default_csv)

    # RULE_FOLDER: override to family-specific dir so rule_lib.get() finds the right files
    # (dataset.py resolves rule paths via RULE_FOLDER env var, not via --rule-folder CLI arg)
    analysis_env["RULE_FOLDER"] = str(rules_dir)

    # GENERATE_RULES_CPUS: auto-detect if not set by user
    if not analysis_env.get("GENERATE_RULES_CPUS", "").strip():
        import multiprocessing
        auto_cpus = max(1, min(8, multiprocessing.cpu_count() // 2))
        analysis_env["GENERATE_RULES_CPUS"] = str(auto_cpus)
    _append_log(family, f"GENERATE_RULES_CPUS: {analysis_env['GENERATE_RULES_CPUS']}")
    _append_log(family, f"APK_FOLDER: {apk_folder}")
    _append_log(family, f"CSV: {csv_path}")

    # Inject PYTHONPATH so local modules (data_preprocess, model, etc.) are importable
    existing_pp = analysis_env.get("PYTHONPATH", "")
    analysis_env["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + existing_pp if existing_pp else "")
    # Disable Python output buffering so subprocess logs appear in real time
    analysis_env["PYTHONUNBUFFERED"] = "1"

    benign_list = analysis_env.get("BENIGN_APK_LIST", "")

    if skip_rule_gen:
        _append_log(family, "⏭ Skipping rule generation (restart from weight adjustment).")
        rules_count = len(list(rules_dir.glob("*.json")))
        if rules_count == 0:
            _append_log(family, "❌ No rules found — cannot skip rule generation.")
            _set_family(family, status=FS.READY, error="No rules found (run rule generation first)")
            return
        _append_log(family, f"Found {rules_count} existing rules.")
        # Jump directly to Step 2
        _append_log(family, "=== Step 2: Adjusting rule weights ===")
        train_csv = _make_train_csv(family, csv_path, safe_family, analysis_env)
        apk_lists = [train_csv]
        if benign_list and Path(benign_list).exists():
            apk_lists.append(benign_list)
        else:
            _append_log(family, "⚠ BENIGN_APK_LIST not configured — training without benign samples.")
        train_cmd = python_cmd + [
            str(PROJECT_ROOT / "tools" / "adjust_rule_score.py"),
            "--target-family", safe_family,
            "--lrs", "0.1,0.05",
            "--epochs", "100",
            "--rule-folder", str(rules_dir),
            "--output-csv", str(pred_csv),
        ]
        for al in apk_lists:
            train_cmd += ["--apk-list", al]
        train_job = f"autotrain_{family}_{datetime.now().strftime('%H%M%S')}"
        pipeline_processes[train_job] = {"status": "pending", "logs": [], "type": "auto_train"}
        _run_script_with_stdin(train_job, train_cmd, str(PROJECT_ROOT), stdin_input="c\nc\n", env=analysis_env, log_family=family)
        _set_family(family, train_job_id=train_job)
        if pipeline_processes[train_job].get("returncode", 1) != 0:
            rc = pipeline_processes[train_job].get("returncode", "?")
            _append_log(family, f"❌ Weight adjustment failed (exit code {rc}).")
            _set_family(family, status=FS.READY, error=f"Weight adjustment failed (exit {rc})")
            return
        _run_post_train_steps(family, pred_csv, rules_dir, rules_count, python_cmd, analysis_env,
                              f"✅ Re-training complete! {rules_count} rules ready.")
        return

    # Step 1: Generate rules — use only N samples (default 1) to keep it fast
    gen_sample_count = int(analysis_env.get("GENERATE_RULES_SAMPLE_COUNT", "1"))
    gen_csv_path = csv_path  # default: full CSV
    if gen_sample_count > 0:
        try:
            rows = Path(csv_path).read_text().splitlines()
            header = rows[0]
            selected = rows[1:gen_sample_count + 1]  # take first N data rows
            tmp_csv = PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}_gen_{gen_sample_count}.csv"
            tmp_csv.write_text("\n".join([header] + selected) + "\n")
            gen_csv_path = str(tmp_csv)
            _append_log(family, f"Rule generation using {len(selected)}/{len(rows)-1} sample(s) (GENERATE_RULES_SAMPLE_COUNT={gen_sample_count}).")
        except Exception as e:
            _append_log(family, f"⚠ Could not create sample CSV ({e}), using full CSV.")

    _append_log(family, "=== Step 1: Generating Quark rules ===")
    gen_job = f"autogen_{family}_{datetime.now().strftime('%H%M%S')}"
    pipeline_processes[gen_job] = {"status": "pending", "logs": [], "type": "auto_generate"}
    _run_script(
        gen_job,
        python_cmd + [str(PROJECT_ROOT / "tools" / "generate_rules.py"),
         "-a", gen_csv_path, "-w", str(working_dir), "-o", str(rules_dir)],
        str(PROJECT_ROOT),
        env=analysis_env,
        log_family=family,
    )
    _set_family(family, gen_job_id=gen_job)

    if pipeline_processes[gen_job].get("returncode", 1) != 0:
        rc = pipeline_processes[gen_job].get("returncode", "?")
        _append_log(family, f"❌ Rule generation failed (exit code {rc}).")
        _set_family(family, status=FS.READY, error=f"Rule generation failed (exit {rc})")
        return

    rules_count = len(list(rules_dir.glob("*.json")))
    _append_log(family, f"✓ Generated {rules_count} rules.")

    if rules_count == 0:
        _append_log(family, "❌ No rules generated — skipping weight adjustment.")
        _append_log(family, "   Hint: GENERATE_RULES_MAX_APIS may be too small (API pool truncated, no combinations matched).")
        _set_family(family, status=FS.READY, error="No rules generated (try increasing GENERATE_RULES_MAX_APIS or remove the limit)")
        return

    # Step 2: Adjust weights
    _append_log(family, "=== Step 2: Adjusting rule weights ===")
    train_csv = _make_train_csv(family, csv_path, safe_family, analysis_env)
    apk_lists = [train_csv]
    if benign_list and Path(benign_list).exists():
        apk_lists.append(benign_list)
        _append_log(family, f"Including benign list: {benign_list}")
    else:
        _append_log(family, "⚠ BENIGN_APK_LIST not configured — training without benign samples.")

    train_cmd = python_cmd + [
        str(PROJECT_ROOT / "tools" / "adjust_rule_score.py"),
        "--target-family", safe_family,
        "--lrs", "0.1,0.05",
        "--epochs", "100",
        "--rule-folder", str(rules_dir),
        "--output-csv", str(pred_csv),
    ]
    for al in apk_lists:
        train_cmd += ["--apk-list", al]

    train_job = f"autotrain_{family}_{datetime.now().strftime('%H%M%S')}"
    pipeline_processes[train_job] = {"status": "pending", "logs": [], "type": "auto_train"}
    _run_script_with_stdin(train_job, train_cmd, str(PROJECT_ROOT), stdin_input="c\nc\n", env=analysis_env, log_family=family)
    _set_family(family, train_job_id=train_job)

    if pipeline_processes[train_job].get("returncode", 1) != 0:
        rc = pipeline_processes[train_job].get("returncode", "?")
        _append_log(family, f"❌ Weight adjustment failed (exit code {rc}).")
        _set_family(family, status=FS.READY, error=f"Weight adjustment failed (exit {rc})")
        return
    _run_post_train_steps(family, pred_csv, rules_dir, rules_count, python_cmd, analysis_env,
                          f"✅ Analysis complete! {rules_count} rules, weights applied.")


def _analysis_wrapper(family: str):
    try:
        _run_analysis(family)
    except Exception as e:
        _set_family(family, status=FS.READY, error=str(e))
        _append_log(family, f"Unexpected error: {e}")


def _analysis_wrapper_train_only(family: str):
    try:
        _run_analysis(family, skip_rule_gen=True)
    except Exception as e:
        _set_family(family, status=FS.READY, error=str(e))
        _append_log(family, f"Unexpected error: {e}")


# ── Queue monitor thread ──
def _queue_monitor():
    while True:
        time.sleep(4)
        try:
            with _state_lock:
                snapshot = {k: dict(v) for k, v in _family_states.items()}

            if any(d.get("status") == FS.ANALYZING for d in snapshot.values()):
                continue

            # Block while COMPLETED or PR_SENT family exists (wait for PR merge)
            if any(d.get("status") in (FS.COMPLETED, FS.PR_SENT) for d in snapshot.values()):
                continue

            queued = sorted(
                [(f, d) for f, d in snapshot.items() if d.get("status") == FS.QUEUED],
                key=lambda x: x[1].get("queued_at", ""),
            )
            if not queued:
                continue

            next_family = queued[0][0]
            _set_family(next_family, status=FS.ANALYZING,
                        analysis_started_at=datetime.now().isoformat())
            _append_log(next_family, "Picked from queue — starting analysis…")
            threading.Thread(target=_analysis_wrapper, args=(next_family,), daemon=True).start()

        except Exception as e:
            print(f"[queue_monitor] {e}")


_load_family_states()
_load_jobs()
threading.Thread(target=_queue_monitor, daemon=True).start()


# ── Pydantic models ──
class AddFamiliesRequest(BaseModel):
    families: list[str]


class SendPRRequest(BaseModel):
    pr_url: str


# ── Endpoints ──
@app.post("/api/auto-pipeline/families")
def add_families(req: AddFamiliesRequest):
    """Add one or more families. Re-adds are allowed only for failed states."""
    added, skipped = [], []
    for raw in req.families:
        family = raw.strip().lower()
        if not family:
            continue
        current = _family_states.get(family, {}).get("status")
        if current and current not in (FS.SEARCH_FAIL, FS.INSUFFICIENT):
            skipped.append(family)
            continue
        _set_family(family, status=FS.SEARCHING, error=None, log=[],
                    bazaar_count=0, downloaded_count=0, failed_count=0)
        threading.Thread(target=_search_and_download, args=(family,), daemon=True).start()
        added.append(family)
    return {"added": added, "skipped": skipped}


@app.get("/api/auto-pipeline/families")
def list_families():
    with _state_lock:
        return dict(_family_states)


@app.get("/api/auto-pipeline/families/{family}")
def get_family(family: str):
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    return _family_states[family]


@app.delete("/api/auto-pipeline/families/{family}")
def remove_family(family: str):
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") in (FS.ANALYZING, FS.QUEUED):
        raise HTTPException(status_code=400, detail="Cannot remove a queued/analyzing family")
    import shutil
    safe_family = _safe_name(family)
    # Delete all associated data on disk
    shutil.rmtree(PROJECT_ROOT / "data" / "apks" / safe_family, ignore_errors=True)
    shutil.rmtree(PROJECT_ROOT / "data" / "generated_rules" / safe_family, ignore_errors=True)
    shutil.rmtree(PROJECT_ROOT / "data" / "rules" / safe_family, ignore_errors=True)
    (PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}.csv").unlink(missing_ok=True)
    with _state_lock:
        del _family_states[family]
        _save_family_states()
    return {"removed": family}


@app.post("/api/auto-pipeline/families/{family}/enqueue")
def enqueue_family(family: str):
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") != FS.READY:
        raise HTTPException(status_code=400, detail="Family must be READY to enqueue")
    _set_family(family, status=FS.QUEUED, queued_at=datetime.now().isoformat())
    return {"family": family, "status": FS.QUEUED}


@app.get("/api/auto-pipeline/families/{family}/rules")
def list_family_rules(family: str):
    """List all rules for a family with score/crime/label metadata."""
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    safe_family = _safe_name(family)
    rules_dir = PROJECT_ROOT / "data" / "rules" / safe_family
    if not rules_dir.exists():
        return {"family": family, "rules": [], "count": 0}
    rules = []
    for rule_path in sorted(rules_dir.glob("*.json")):
        try:
            content = json.loads(rule_path.read_text())
            rules.append({
                "name": rule_path.name,
                "score": content.get("score"),
                "crime": content.get("crime", ""),
                "label": content.get("label", []),
            })
        except Exception:
            rules.append({"name": rule_path.name, "score": None, "crime": "", "label": []})
    rules.sort(key=lambda r: (r["score"] is None, -(r["score"] or 0)))
    return {"family": family, "rules": rules, "count": len(rules)}


@app.get("/api/auto-pipeline/families/{family}/rules/{rule_name}")
def get_family_rule(family: str, rule_name: str):
    """Get full JSON content of a single rule."""
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    safe_family = _safe_name(family)
    rule_path = PROJECT_ROOT / "data" / "rules" / safe_family / rule_name
    if not rule_path.exists():
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        content = json.loads(rule_path.read_text())
        return {"name": rule_name, "content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read rule: {e}")


@app.post("/api/auto-pipeline/families/{family}/pr")
def record_pr(family: str, req: SendPRRequest):
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") != FS.COMPLETED:
        raise HTTPException(status_code=400, detail="Family must be COMPLETED")
    _set_family(family, status=FS.PR_SENT, pr_url=req.pr_url,
                pr_sent_at=datetime.now().isoformat())
    return {"family": family, "status": FS.PR_SENT}


@app.post("/api/auto-pipeline/families/{family}/pr/merged")
def mark_merged(family: str):
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") != FS.PR_SENT:
        raise HTTPException(status_code=400, detail="Family must be in PR_SENT state")
    _set_family(family, status=FS.PR_MERGED, pr_merged_at=datetime.now().isoformat())
    return {"family": family, "status": FS.PR_MERGED}


@app.delete("/api/auto-pipeline/families/{family}/rules")
def clear_rules(family: str):
    """Delete generated rules for a family so they can be regenerated."""
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") == FS.ANALYZING:
        raise HTTPException(status_code=400, detail="Cannot clear rules while analyzing")

    import shutil
    safe_family = _safe_name(family)
    for d in [
        PROJECT_ROOT / "data" / "generated_rules" / safe_family,
        PROJECT_ROOT / "data" / "rules" / safe_family,
    ]:
        shutil.rmtree(d, ignore_errors=True)

    _append_log(family, "🗑 Generated rules cleared. Re-enqueue to regenerate.")
    _set_family(family, rules_count=None, rules_path=None, prediction_csv=None,
                gen_job_id=None, train_job_id=None,
                status=FS.READY if _family_states[family].get("status") in (FS.COMPLETED, "pr_sent", "pr_merged") else _family_states[family].get("status"),
                error=None)
    return {"family": family, "cleared": True}


@app.post("/api/auto-pipeline/families/{family}/stop")
def stop_family(family: str):
    """Kill the running analysis for a family and reset it to READY for re-queuing."""
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") != FS.ANALYZING:
        raise HTTPException(status_code=400, detail="Family is not currently analyzing")

    # Kill subprocess via gen_job or train_job PID
    killed = False
    for job_key in ("gen_job_id", "train_job_id"):
        job_id = _family_states[family].get(job_key)
        if not job_id:
            continue
        pid = pipeline_processes.get(job_id, {}).get("pid")
        if pid:
            try:
                import signal
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                killed = True
            except Exception:
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed = True
                except Exception:
                    pass

    _append_log(family, f"⏹ Analysis stopped by user (killed={killed}). Progress saved in cache — re-enqueue to resume.")
    _set_family(family, status=FS.READY, error="已手動停止（可重新加入佇列繼續）")
    return {"family": family, "status": FS.READY, "killed": killed}


@app.post("/api/auto-pipeline/families/{family}/retry")
def retry_family(family: str):
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") not in (FS.SEARCH_FAIL, FS.INSUFFICIENT):
        raise HTTPException(status_code=400, detail="Only failed families can be retried")
    _set_family(family, status=FS.SEARCHING, error=None, log=[],
                bazaar_count=0, downloaded_count=0, failed_count=0)
    threading.Thread(target=_search_and_download, args=(family,), daemon=True).start()
    return {"family": family, "status": FS.SEARCHING}


@app.post("/api/auto-pipeline/families/{family}/restart/search")
def restart_search(family: str):
    """Re-run from Stage 1: delete all data and restart from MalwareBazaar search."""
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") in (FS.ANALYZING, FS.QUEUED):
        raise HTTPException(status_code=400, detail="Cannot restart while analyzing/queued")
    import shutil
    safe_family = _safe_name(family)
    shutil.rmtree(PROJECT_ROOT / "data" / "apks" / safe_family, ignore_errors=True)
    shutil.rmtree(PROJECT_ROOT / "data" / "generated_rules" / safe_family, ignore_errors=True)
    shutil.rmtree(PROJECT_ROOT / "data" / "rules" / safe_family, ignore_errors=True)
    (PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}.csv").unlink(missing_ok=True)
    _set_family(family, status=FS.SEARCHING, error=None, log=[],
                bazaar_count=0, downloaded_count=0, failed_count=0,
                rules_count=None, rules_path=None, prediction_csv=None,
                apk_folder=None, csv_path=None)
    threading.Thread(target=_search_and_download, args=(family,), daemon=True).start()
    return {"family": family, "status": FS.SEARCHING}


@app.post("/api/auto-pipeline/families/{family}/restart/download")
def restart_download(family: str):
    """Re-run from Stage 2: delete APKs and re-download (keeps MalwareBazaar search result)."""
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") in (FS.ANALYZING, FS.QUEUED):
        raise HTTPException(status_code=400, detail="Cannot restart while analyzing/queued")
    import shutil
    safe_family = _safe_name(family)
    shutil.rmtree(PROJECT_ROOT / "data" / "apks" / safe_family, ignore_errors=True)
    shutil.rmtree(PROJECT_ROOT / "data" / "generated_rules" / safe_family, ignore_errors=True)
    shutil.rmtree(PROJECT_ROOT / "data" / "rules" / safe_family, ignore_errors=True)
    (PROJECT_ROOT / "data" / "lists" / "family" / f"{safe_family}.csv").unlink(missing_ok=True)
    _set_family(family, status=FS.SEARCHING, error=None,
                downloaded_count=0, failed_count=0,
                rules_count=None, rules_path=None, prediction_csv=None,
                apk_folder=None, csv_path=None)
    _append_log(family, "🔄 Re-downloading APKs from scratch…")
    threading.Thread(target=_search_and_download, args=(family,), daemon=True).start()
    return {"family": family, "status": FS.SEARCHING}


@app.post("/api/auto-pipeline/families/{family}/restart/train")
def restart_train(family: str):
    """Re-run from Stage 4: skip rule generation, re-run weight adjustment only."""
    if family not in _family_states:
        raise HTTPException(status_code=404, detail="Family not found")
    if _family_states[family].get("status") in (FS.ANALYZING, FS.QUEUED):
        raise HTTPException(status_code=400, detail="Cannot restart while analyzing/queued")
    info = _family_states[family]
    safe_family = _safe_name(family)
    rules_dir = PROJECT_ROOT / "data" / "rules" / safe_family
    if not list(rules_dir.glob("*.json")):
        raise HTTPException(status_code=400, detail="No rules found — run rule generation first")
    _set_family(family, status=FS.ANALYZING, prediction_csv=None,
                analysis_started_at=datetime.now().isoformat())
    _append_log(family, "🔄 Restarting from Stage 4: weight adjustment only…")
    threading.Thread(target=_analysis_wrapper_train_only, args=(family,), daemon=True).start()
    return {"family": family, "status": FS.ANALYZING}


# ──────────────────────────────────────────────
# Test Analysis
# ──────────────────────────────────────────────

@app.get("/api/test/resources")
def get_test_resources():
    """List available APK CSV lists and rule folders for test analysis."""
    # Scan locations for APK CSV files
    csv_search_roots = [
        PROJECT_ROOT / "data" / "lists",
        PROJECT_ROOT,  # project-root level (demo files like maliciousAPKs_test.csv)
    ]
    # Scan locations for rule folders
    rule_search_roots = [
        PROJECT_ROOT / "data" / "rules",
        PROJECT_ROOT,  # project-root level (demo folder like test_rules/)
    ]

    def count_rows(csv_file: Path) -> int:
        try:
            with open(csv_file) as f:
                return max(0, sum(1 for _ in f) - 1)
        except Exception:
            return 0

    seen_csv: set[str] = set()
    apk_lists = []
    for root in csv_search_roots:
        if not root.exists():
            continue
        # For project root, only look at direct *.csv files (not recursive)
        glob = root.glob("*.csv") if root == PROJECT_ROOT else root.rglob("*.csv")
        for csv_file in sorted(glob):
            rel = str(csv_file.relative_to(PROJECT_ROOT))
            if rel in seen_csv:
                continue
            seen_csv.add(rel)
            # Only include CSVs that have a 'sha256' column header
            try:
                with open(csv_file) as f:
                    header = f.readline().strip().lower()
                if "sha256" not in header:
                    continue
            except Exception:
                continue
            demo = csv_file.parent == PROJECT_ROOT
            apk_lists.append({"name": csv_file.name, "path": rel, "rows": count_rows(csv_file), "demo": demo})

    seen_dirs: set[str] = set()
    rule_folders = []
    for root in rule_search_roots:
        if not root.exists():
            continue
        for folder in sorted(root.iterdir()):
            if not folder.is_dir():
                continue
            count = len(list(folder.glob("*.json")))
            if count == 0:
                continue
            rel = str(folder.relative_to(PROJECT_ROOT))
            if rel in seen_dirs:
                continue
            seen_dirs.add(rel)
            demo = folder.parent == PROJECT_ROOT
            rule_folders.append({"name": folder.name, "path": rel, "count": count, "demo": demo})

    return {"apk_lists": apk_lists, "rule_folders": rule_folders}


class TestRunRequest(BaseModel):
    apk_lists: list[str]
    rule_folders: list[str]
    output_name: str = ""
    use_cache: bool = True


@app.post("/api/test/run")
def run_test_analysis(req: TestRunRequest):
    """Run analyze_apk.py on selected APK lists and rule folders."""
    if not req.apk_lists:
        raise HTTPException(status_code=400, detail="至少選擇一個 APK 清單")
    if not req.rule_folders:
        raise HTTPException(status_code=400, detail="至少選擇一個規則資料夾")

    def resolve(p: str) -> Path:
        path = Path(p)
        return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()

    apk_list_paths = [resolve(p) for p in req.apk_lists]
    rule_folder_paths = [resolve(p) for p in req.rule_folders]

    for p in apk_list_paths:
        if not p.exists():
            raise HTTPException(status_code=400, detail=f"找不到 APK 清單: {p}")
    for p in rule_folder_paths:
        if not p.exists():
            raise HTTPException(status_code=400, detail=f"找不到規則資料夾: {p}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = (req.output_name.strip() or f"test_{ts}").replace(" ", "_")
    output_dir = PROJECT_ROOT / "data" / "test_results" / out_name
    output_dir.mkdir(parents=True, exist_ok=True)

    python_cmd = _get_analysis_python()
    cmd = python_cmd + [str(PROJECT_ROOT / "tools" / "analyze_apk.py")]
    for p in apk_list_paths:
        cmd += ["-a", str(p)]
    for p in rule_folder_paths:
        cmd += ["-r", str(p)]
    cmd += ["-o", str(output_dir)]
    if not req.use_cache:
        cmd += ["--no-cache"]

    analysis_env = os.environ.copy()
    if ENV_FILE.exists():
        for k, v in dotenv.dotenv_values(ENV_FILE).items():
            if v is not None:
                analysis_env[k] = v
    existing_pp = analysis_env.get("PYTHONPATH", "")
    analysis_env["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + existing_pp if existing_pp else "")
    analysis_env["PYTHONUNBUFFERED"] = "1"

    job_id = f"test_{ts}"
    pipeline_processes[job_id] = {
        "status": "pending", "logs": [], "type": "test_analysis",
        "output_dir": str(output_dir),
    }
    asyncio.get_event_loop().run_in_executor(None, _run_script, job_id, cmd, str(PROJECT_ROOT), analysis_env)
    return {"job_id": job_id, "output_dir": str(output_dir)}


@app.get("/api/test/result/{job_id}")
def get_test_result(job_id: str):
    """Read combined output CSVs from a completed test analysis job."""
    if job_id not in pipeline_processes:
        raise HTTPException(status_code=404, detail="Job not found")
    info = pipeline_processes[job_id]
    output_dir = Path(info.get("output_dir", ""))
    if not output_dir.exists():
        return {"rows": [], "columns": [], "message": "結果尚未生成"}
    try:
        import csv
        all_rows = []
        columns: list[str] = []
        for csv_file in sorted(output_dir.rglob("*.csv")):
            with open(csv_file, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if not columns and reader.fieldnames:
                    columns = list(reader.fieldnames)
                for row in reader:
                    all_rows.append(dict(row))
                    if len(all_rows) >= 2000:
                        break
            if len(all_rows) >= 2000:
                break
        return {"rows": all_rows, "columns": columns, "total": len(all_rows)}
    except Exception as e:
        return {"rows": [], "columns": [], "message": str(e)}


@app.get("/api/test/history-result")
def get_test_history_result(name: str):
    """Read combined output CSVs from a named test result directory."""
    results_root = PROJECT_ROOT / "data" / "test_results"
    output_dir = (results_root / name).resolve()
    # Safety: ensure it's within test_results
    if not str(output_dir).startswith(str(results_root)):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not output_dir.exists():
        return {"rows": [], "columns": [], "message": "結果目錄不存在"}
    try:
        import csv
        all_rows = []
        columns: list[str] = []
        for csv_file in sorted(output_dir.rglob("*.csv")):
            with open(csv_file, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if not columns and reader.fieldnames:
                    columns = list(reader.fieldnames)
                for row in reader:
                    all_rows.append(dict(row))
                    if len(all_rows) >= 2000:
                        break
            if len(all_rows) >= 2000:
                break
        return {"rows": all_rows, "columns": columns, "total": len(all_rows)}
    except Exception as e:
        return {"rows": [], "columns": [], "message": str(e)}


@app.get("/api/test/history")
def get_test_history():
    """List past test result directories."""
    results_root = PROJECT_ROOT / "data" / "test_results"
    if not results_root.exists():
        return {"results": []}
    items = []
    for d in sorted(results_root.iterdir(), reverse=True):
        if d.is_dir():
            csv_count = len(list(d.rglob("*.csv")))
            items.append({"name": d.name, "csv_count": csv_count})
    return {"results": items[:50]}


# ──────────────────────────────────────────────
# Frontend
# ──────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

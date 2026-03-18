# Rule Score Auto Adjust - Project Skill

## Project Overview

**Rule Score Auto Adjust** is an automated Android malware detection pipeline that generates Quark-Engine rules for malware families and optimizes their detection scores using machine learning.

- **Purpose**: Detect and classify Android malware by generating rules specific to malware families, then training neural networks to optimize rule weights
- **Tech Stack**: FastAPI backend + vanilla HTML/JS frontend + Python CLI tools + Quark-Engine + PyTorch + MLflow
- **Data Flow**: MalwareBazaar → APK Download → Rule Generation → Weight Training → Rule JSON Output → quark-rules repo (optional PR)

---

## Architecture Overview

### Frontend & Backend Structure
```
rule_score_auto_adjust/
├── web/
│   ├── app.py              # FastAPI backend (state mgmt, pipeline endpoints, settings UI API)
│   └── static/
│       └── index.html      # Single-page React-like app (Settings, Pipeline Monitor, Auto Pipeline UI)
├── tools/                  # CLI scripts for each pipeline step
│   ├── generate_rules.py   # Generate Quark rules from APKs (Ray + Prefect)
│   ├── adjust_rule_score.py # Train weights for rules (PyTorch + MLflow)
│   ├── analyze_apk.py      # Analyze APK against rules (Ray)
│   ├── apply_rule_info.py  # Apply optimized scores back to rule JSONs
│   ├── copy_rule_to_quark_rules.py # Copy rules to quark-rules repo
│   ├── collect_apk_by_family.py    # Download APKs from MalwareBazaar/AndroZoo
│   └── ...                 # Other helpers
├── data/
│   ├── apks/               # Downloaded APK files (organized by family)
│   ├── rules/              # Generated rule JSON files (organized by family)
│   ├── generated_rules/    # Intermediate rule generation output
│   ├── predictions/        # Prediction CSVs from training (apk_prediction.csv)
│   ├── lists/family/       # Metadata CSVs (sample lists, rule reviews, predictions)
│   ├── auto_pipeline_state.json   # Auto pipeline family states (persisted)
│   ├── jobs_history.json   # Completed job metadata (last 100 jobs)
│   └── dataset/            # Cache for dataset preprocessing
├── .env                    # Configuration (API keys, paths, parameters)
└── README.md              # Setup & usage instructions
```

---

## The 5-Stage Auto Pipeline

The **Auto Pipeline** automates the full workflow for a malware family from search to rule generation. Stages are tracked in `_family_states` dict and persisted to `auto_pipeline_state.json`.

### Stage 1: Search + Download
- **Status**: `SEARCHING` → `DOWNLOADING` → `READY` or `SEARCH_FAIL` / `INSUFFICIENT`
- **Function**: `_search_and_download(family: str)` (runs in background thread)
- **Steps**:
  1. Query MalwareBazaar API for samples of the malware family (limit 100)
  2. Check if count ≥ `MIN_SAMPLES` env var (default 10)
  3. Download APKs from AndroZoo API (limit: `MAX_APK_DOWNLOAD`, default 100)
  4. Skip if less than `MIN_SAMPLES` downloaded
  5. Save SHA256 list to `data/lists/family/{safe_family}.csv`
  6. Save APKs to `data/apks/{safe_family}/`
- **Output**:
  - Family state: `csv_path`, `apk_folder`, `downloaded_count`
  - Files: `data/apks/{safe_family}/*.apk`, `data/lists/family/{safe_family}.csv`

### Stage 2: Queue + Rule Generation
- **Status**: `READY` → `QUEUED` → `ANALYZING` → `COMPLETED` or error
- **Function**: `_run_analysis(family, skip_rule_gen=False)` (runs in background thread)
- **Sub-Step 2a: Rule Generation**
  - Calls `tools/generate_rules.py` via subprocess
  - Input: `data/apks/{safe_family}/*.apk`
  - Output: `data/rules/{safe_family}/*.json` (Quark rule files)
  - Uses Ray for distributed rule generation (configurable CPUs/memory)
  - Logs streamed to family log in real-time via `_append_log_mem()`

### Stage 3: Weight Adjustment (Training)
- **Sub-Step 2b: Model Training**
  - Calls `tools/adjust_rule_score.py` via subprocess
  - Input: `data/lists/family/{safe_family}.csv` + benign APK list
  - Trains PyTorch model to optimize rule weights
  - MLflow tracks training metrics
  - Output: `data/predictions/{safe_family}_prediction.csv`

### Stage 4: Score Application
- **Sub-Step 2c: Apply Scores**
  - Calls `tools/apply_rule_info.py` via subprocess
  - Updates rule JSON files with optimized scores
  - Optional: applies rule descriptions from `{safe_family}_rule_review.csv`
  - Output: Updated `data/rules/{safe_family}/*.json`

### Stage 5: Copy to quark-rules (Optional)
- **Sub-Step 2d: Copy Rules**
  - Calls `tools/copy_rule_to_quark_rules.py` via subprocess (if `QUARK_RULES_FOLDER` configured)
  - Copies optimized rules to quark-rules repo
  - Auto-assigns rule indices
  - Final status: `COMPLETED`

---

## Key Tools (CLI Scripts)

All tools run via `uv run tools/{script}.py` and support configurable parameters via CLI or environment variables.

### `tools/generate_rules.py`
**Generates Quark detection rules from APK samples using Quark-Engine.**

CLI Interface:
```bash
uv run tools/generate_rules.py \
  -a <apk_list_csv> \
  -w <working_folder> \
  -o <output_folder> \
  [--rerun_failed]
```

Key Features:
- Uses `quark.rulegeneration.RuleGeneration` to extract rules
- Ray + Prefect for distributed processing
- Environment variables:
  - `GENERATE_RULES_CPUS`: Worker count (default: CPU_count // 2, max 8)
  - `GENERATE_RULES_OBJECT_STORE_MB`: Ray memory per worker (default 2048 MB, capped 2048 on macOS)
  - `GENERATE_RULES_MAX_APIS`: Limit API pool size for testing (0 = unlimited)
- Output: `{output_folder}/*.json` (one rule per APK)

### `tools/adjust_rule_score.py`
**Trains a PyTorch model to optimize rule scores for accurate malware detection.**

CLI Interface:
```bash
uv run tools/adjust_rule_score.py \
  --target-family <family_name> \
  --apk-list <csv> \
  --rule-folder <path> \
  --lrs <learning_rates> \
  --epochs <int> \
  --output-csv <path> \
  [--run-id <mlflow_run_id>]
```

Key Features:
- Uses `model.RuleAdjustmentModel` (PyTorch-based)
- Requires benign APK list: `BENIGN_APK_LIST` env var
- MLflow tracking for metrics (accuracy, precision, recall, F1)
- Supports resuming prior runs with `--run-id`
- Environment variables:
  - `TRAIN_SAMPLE_COUNT`: Limit training samples (0 = unlimited, default 10)
  - `BENIGN_APK_LIST`: Path to CSV of benign APK SHA256s
  - `ANALYSIS_PYTHON`: Custom Python executable for analysis (fallback: sys.executable)
- Output: `{output_csv}` (predictions on test set)

### `tools/analyze_apk.py`
**Analyzes APKs against Quark rules to generate predictions.**

Key Features:
- Uses Ray for distributed analysis
- Runs Quark rule engine against APK files
- Caches analysis results to avoid re-computation
- Output: DataFrame with confidence scores per rule

### `tools/apply_rule_info.py`
**Applies optimized rule scores back to rule JSON files and adds metadata.**

CLI Interface:
```bash
uv run tools/apply_rule_info.py \
  --apk_prediction <csv> \
  --rule_info <csv> \
  --rule_base_folder <path> \
  [-s]  # --revert_score flag
```

Inputs:
- `apk_prediction`: Predictions CSV from training
- `rule_info`: Rule descriptions/labels CSV (`{safe_family}_rule_review.csv`)
- `rule_base_folder`: Folder with generated rule JSONs

Output: Updated rule JSONs with optimized confidence scores

### `tools/collect_apk_by_family.py`
**Downloads APKs for a malware family from MalwareBazaar/AndroZoo (manual collection, also used by auto pipeline).**

CLI Interface:
```bash
uv run tools/collect_apk_by_family.py \
  -a <apk_list_csv> \
  -f <family_name> \
  -o <output_path>
```

### `tools/copy_rule_to_quark_rules.py`
**Copies generated rules to the quark-rules repository with auto-assigned indices.**

CLI Interface:
```bash
uv run tools/copy_rule_to_quark_rules.py \
  --rule_list <csv> \
  --rule_base_folder <path> \
  --quark_rule_folder <path> \
  --start_index <int>
```

---

## Key Files

### Backend: `web/app.py`
FastAPI application with three main sections:

#### 1. **Query Endpoints** (MalwareBazaar, AndroZoo)
- `GET /api/malwarebazaar/search?signature=<family>&limit=50` – Search for samples
- `GET /api/malwarebazaar/recent?limit=100` – Get recent APK samples
- `GET /api/androzoo/check/{sha256}` – Check if APK exists in AndroZoo

#### 2. **Pipeline Job Management**
- `POST /api/pipeline/train` – Start `adjust_rule_score.py`
- `POST /api/pipeline/generate-rules` – Start `generate_rules.py`
- `POST /api/pipeline/collect-apk-by-family` – Start `collect_apk_by_family.py`
- `POST /api/pipeline/apply-rule-info` – Start `apply_rule_info.py`
- `GET /api/pipeline/jobs` – List all jobs with status/type/metadata
- `GET /api/pipeline/jobs/{job_id}` – Get job details + logs (paginated by offset)
- `DELETE /api/pipeline/jobs/{job_id}` – Remove job from history

#### 3. **Configuration & Settings**
- `GET /api/config/check` – Check which env vars are set
- `GET /api/config/python-check` – Verify analysis Python + required packages
- `GET /api/settings` – Read current .env values (secrets masked)
- `POST /api/settings` – Save .env settings (empty string = skip/keep existing)

#### 4. **Filesystem Browser**
- `GET /api/fs/browse?path=~` – List directory contents (for path picker)

#### 5. **Auto Pipeline Endpoints**
- `POST /api/auto/start` – Start auto pipeline for a family
- `GET /api/auto/families` – List all families and their states
- `GET /api/auto/families/{family}` – Get detailed family state + logs
- `POST /api/auto/queue/{family}` – Queue a family for analysis (after successful download)
- `DELETE /api/auto/families/{family}` – Remove family from tracking

### State Management in `app.py`

**In-Memory State:**
- `pipeline_processes: dict[str, dict]` – Tracks all running/completed jobs (loaded from disk on startup)
- `_family_states: dict[str, dict]` – Auto pipeline family states (one entry per family)
- `_state_lock: threading.Lock()` – Protects concurrent access to `_family_states`

**Persisted State (on disk):**
- `data/auto_pipeline_state.json` – Family states (status, counts, logs, timestamps)
- `data/jobs_history.json` – Last 100 completed jobs (metadata + last 500 log lines per job)

**Key Functions:**
- `_load_family_states()` – Load from disk, reset stuck states on startup
- `_save_family_states()` – Atomic write (tmp file → rename) to prevent corruption
- `_set_family(family, **kwargs)` – Update family state + save atomically
- `_append_log(family, line)` – Add timestamped log line to family log (max 300 lines)
- `_append_log_mem(family, line)` – Add log line in-memory only (called from subprocess output stream)

### Frontend: `web/static/index.html`
Single-page HTML app with React-like component architecture:
- **Settings Tab**: Read/write .env values, test Python environment
- **Pipeline Monitor Tab**: View running/completed jobs, stream logs
- **Auto Pipeline Tab**: Start new families, queue for analysis, monitor progress

### Data Directories

```
data/
├── apks/
│   └── {safe_family}/        # APK downloads for each family
│       ├── {sha256}.apk
│       └── ...
├── rules/
│   └── {safe_family}/        # Optimized Quark rule JSONs
│       ├── {rule_name}.json
│       └── ...
├── generated_rules/
│   └── {safe_family}/        # Intermediate rule generation output
├── predictions/
│   └── {safe_family}_prediction.csv  # Test set predictions from training
├── lists/family/
│   ├── {safe_family}.csv            # SHA256 list (header: sha256,is_malicious)
│   ├── {safe_family}_train_*.csv    # Truncated training set (if TRAIN_SAMPLE_COUNT < total)
│   ├── {safe_family}_rule_review.csv # Rule metadata (rule, description, label)
│   ├── {safe_family}_rule_list.csv  # List of rule names (for copy_rule_to_quark_rules)
│   └── ...
├── dataset/                          # Cache for dataset preprocessing
├── auto_pipeline_state.json          # Persisted family states
└── jobs_history.json                 # Persisted job history
```

---

## Environment Variables

Essential variables (read from `.env` file at startup and via Settings UI):

### API Keys
- `MALWAREBAZAAR_API_KEY` – Required for searching families
- `ANDROZOO_API_KEY` – Required for downloading APKs
- `VIRUS_TOTAL_API_KEY` – Optional (for additional validation)
- `OPENAI_API_KEY` – Optional (for rule description generation)

### Paths
- `APK_FOLDER` – Default: `/mnt/storage/data/apks` (may be overridden by `data/apks/` for local dev)
- `RULE_FOLDER` – Default: `/mnt/storage/data/generated_rules`
- `ANALYSIS_RESULT_FOLDER` – Default: `/mnt/storage/data/analysis_results`
- `DATASET_CACHE_FOLDER` – Default: `data/dataset` (relative, stored in project root)
- `CACHE_FOLDER` – Default: `/mnt/storage/data/cache`
- `BENIGN_APK_LIST` – Path to CSV of benign APK SHA256s (required for training)
- `QUARK_RULES_FOLDER` – Path to quark-rules repo (leave empty to skip copy step)

### Tool Parameters
- `GENERATE_RULES_CPUS` – Worker count for rule generation (default: CPU_count // 2, max 8)
- `GENERATE_RULES_OBJECT_STORE_MB` – Ray memory per worker (default 2048, capped on macOS)
- `GENERATE_RULES_MAX_APIS` – Limit API pool for testing (0 = unlimited)
- `GENERATE_RULES_SAMPLE_COUNT` – Max APKs to process (0 = all)
- `TRAIN_SAMPLE_COUNT` – Training set size (0 = unlimited, default 10)
- `MIN_SAMPLES` – Min downloaded APKs required to proceed (default 10)
- `MAX_APK_DOWNLOAD` – Max APKs to download per family (default 100)
- `QUARK_RULES_START_INDEX` – First rule index for copy step (default 1)

### Analysis Environment
- `ANALYSIS_PYTHON` – Custom Python executable for analysis (e.g., `/opt/analysis-env/bin/python`)
- `PYTHONPATH` – Set to `.` for local imports (default in .env.template)

---

## Data Flow Examples

### Example 1: Manual Rule Generation
```
1. User uploads SHA256 CSV (data/lists/family/malware.csv)
2. POST /api/pipeline/generate-rules
   └─→ uv run tools/generate_rules.py -a data/lists/family/malware.csv -o data/rules/
3. Ray + Prefect distribute rule generation across CPUs
4. Output: data/rules/*.json (one per APK)
```

### Example 2: Auto Pipeline for "ToxicPanda"
```
1. POST /api/auto/start?family=ToxicPanda
2. Background thread: _search_and_download("ToxicPanda")
   └─→ Query MalwareBazaar API
   └─→ Download APKs from AndroZoo
   └─→ Save CSV + APKs
   └─→ Status: READY
3. User clicks "Queue for Analysis"
   └─→ Status: QUEUED
4. Background thread: _run_analysis("ToxicPanda")
   └─→ Subprocess: tools/generate_rules.py
   └─→ Subprocess: tools/adjust_rule_score.py (training)
   └─→ Subprocess: tools/apply_rule_info.py
   └─→ Optional: tools/copy_rule_to_quark_rules.py
   └─→ Status: COMPLETED
5. Optimized rules ready in data/rules/toxicpanda/
```

---

## Common Issues & Fixes

### Issue: Subprocess output not showing in logs
**Cause**: Default Python buffering delays output
**Fix**: Set `PYTHONPATH=.` and use `bufsize=1` in Popen (already applied in `_run_script()`)
**Location**: `web/app.py` line 231-238

### Issue: Cross-machine APK paths failing
**Cause**: Hard-coded `/mnt/storage/...` paths on different machines
**Fix**: Fallback logic in tools: if `APK_FOLDER` not found, try `data/apks/` (project-relative)
**Location**: Check each tool's path handling

### Issue: Production crashes from excessive logging
**Cause**: `-–reload` flag in development spawns multiple FastAPI processes
**Fix**: Use production start script without `-–reload`
**Location**: `start.sh` (if exists)

### Issue: State file corruption on server crash
**Cause**: Atomic writes not used
**Fix**: Atomic write pattern: `tmp.write_text(...); tmp.replace(target)` (already applied)
**Location**: `_save_family_states()`, `_save_completed_job()` (line 664-666, 691-693)

### Issue: Family stuck in ANALYZING/QUEUED after restart
**Cause**: Subprocess killed, state never updated
**Fix**: Load states on startup and reset stuck families to READY
**Location**: `_load_family_states()` (line 678-686)

### Issue: subprocess.STDOUT merge not showing stderr
**Cause**: STDOUT/STDERR are separate file descriptors
**Fix**: Use `stderr=subprocess.STDOUT` in Popen (already applied)
**Location**: `_run_script()` line 236

---

## Web API Endpoints Summary

### MalwareBazaar
- `GET /api/malwarebazaar/search?signature=<family>&limit=50`
- `GET /api/malwarebazaar/recent?limit=100`

### AndroZoo
- `GET /api/androzoo/check/{sha256}`

### Pipeline Jobs
- `POST /api/pipeline/train`
- `POST /api/pipeline/generate-rules`
- `POST /api/pipeline/collect-apk-by-family`
- `POST /api/pipeline/apply-rule-info`
- `GET /api/pipeline/jobs`
- `GET /api/pipeline/jobs/{job_id}`
- `DELETE /api/pipeline/jobs/{job_id}`

### Config & Settings
- `GET /api/config/check`
- `GET /api/config/python-check`
- `GET /api/settings`
- `POST /api/settings`

### Filesystem
- `GET /api/fs/browse?path=~`

### Auto Pipeline
- `POST /api/auto/start?family=<name>`
- `GET /api/auto/families`
- `GET /api/auto/families/{family}`
- `POST /api/auto/queue/{family}`
- `DELETE /api/auto/families/{family}`

---

## Development Tips

### Running the Web Server
```bash
# Development (with reload)
uv run uvicorn web.app:app --reload --port 8000

# Production (no reload)
uvicorn web.app:app --port 8000 --workers 1
```

### Testing a Tool Manually
```bash
# Load .env and run
set -a && source .env && set +a
uv run tools/generate_rules.py -a data/lists/family/test.csv -o data/rules/
```

### Monitoring Auto Pipeline
1. Open http://localhost:8000 (frontend)
2. Go to "Auto Pipeline" tab
3. View family status and live logs

### Debugging State Issues
```bash
# Read current family states
cat data/auto_pipeline_state.json | jq .

# Read job history
cat data/jobs_history.json | jq . | head -50
```

### Path Compatibility
When writing tools, use this pattern for path resolution:
```python
from pathlib import Path
import os

# Prefer configured path, fallback to project-relative
apk_folder = os.getenv("APK_FOLDER", "")
if not apk_folder or not Path(apk_folder).exists():
    apk_folder = Path(__file__).parent.parent / "data" / "apks"
```

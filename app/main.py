import asyncio
import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

app = FastAPI(title="Ansible Security Repair")
MAX_CYCLES = 5
COMMAND_TIMEOUT_SECONDS = 180
MAX_UPLOAD_BYTES = 500_000
jobs: dict[str, dict[str, Any]] = {}


def yaml_only(model_text: str) -> str:
    """Return only a syntactically valid YAML playbook; never return LLM prose."""
    delimited = re.findall(r"<REPAIRED_PLAYBOOK>\s*(.*?)\s*</REPAIRED_PLAYBOOK>", model_text, re.I | re.S)
    fenced = re.findall(r"```(?:yaml|yml)?\s*\n(.*?)```", model_text, re.I | re.S)
    for candidate in delimited + fenced:
        cleaned = candidate.strip()
        try:
            parsed = yaml.safe_load(cleaned)
            if isinstance(parsed, list) and parsed:
                return cleaned
        except yaml.YAMLError:
            continue
    raise ValueError("Antigravity did not return a valid Ansible playbook.")


async def run_command(command: list[str], directory: str, timeout: int = COMMAND_TIMEOUT_SECONDS) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        *command, cwd=directory, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        return 124, f"Timed out after {timeout} seconds."
    return process.returncode, output.decode("utf-8", errors="replace")[-20_000:]


def parse_json_output(output: str) -> Any:
    """Scanner versions sometimes emit a JSON object amid harmless status lines."""
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        match = re.search(r"(?s)(\{.*\}|\[.*\])", output)
        if match:
            return json.loads(match.group(1))
    raise ValueError("Scanner did not produce readable JSON.\n" + output[-2500:])


async def scan_playbook(directory: str, filename: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    lint_code, lint_output = await run_command(["ansible-lint", "-f", "json", filename], directory)
    checkov_code, checkov_output = await run_command(["checkov", "-f", filename, "-o", "json"], directory)
    lint_issues: list[dict[str, str]] = []
    checkov_issues: list[dict[str, str]] = []
    try:
        lint_data = parse_json_output(lint_output) if lint_output.strip() else []
        if isinstance(lint_data, list):
            lint_issues = [{
                "tool": "ansible-lint", "id": str(item.get("check_name", item.get("rule", {}).get("id", item.get("tag", "lint")))),
                "severity": str(item.get("level", "medium")), "location": str(item.get("location", {}).get("path", filename)),
                "message": str(item.get("message", "Ansible lint finding")),
            } for item in lint_data if isinstance(item, dict)]
    except ValueError as exc:
        if lint_code not in (0,):
            lint_issues = [{"tool": "ansible-lint", "id": "scanner-error", "severity": "high", "location": filename, "message": str(exc)}]
    try:
        checkov_data = parse_json_output(checkov_output) if checkov_output.strip() else {}
        failed = checkov_data.get("results", {}).get("failed_checks", []) if isinstance(checkov_data, dict) else []
        checkov_issues = [{
            "tool": "checkov", "id": str(item.get("check_id", "checkov")),
            "severity": str(item.get("severity") or "medium"), "location": str(item.get("file_path", filename)),
            "message": str(item.get("check_name", "Checkov security finding")),
        } for item in failed if isinstance(item, dict)]
    except ValueError as exc:
        if checkov_code not in (0, 1):
            checkov_issues = [{"tool": "checkov", "id": "scanner-error", "severity": "high", "location": filename, "message": str(exc)}]
    return lint_issues, checkov_issues


def antigravity_response(prompt: str, workspace: str, continue_session: bool) -> str:
    command = ["agy"]
    if continue_session:
        command.append("--continue")
    command.extend(["-p", prompt, "--output-format", "json"])
    completed = subprocess.run(command, cwd=workspace, text=True, capture_output=True, timeout=180, check=False)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        if any(word in detail.lower() for word in ("login", "sign in", "oauth", "authenticat")):
            raise RuntimeError("Antigravity is not authenticated. Complete the OAuth sign-in first.")
        raise RuntimeError("Antigravity CLI failed:\n" + detail[-3000:])
    try:
        return json.loads(completed.stdout).get("response", "")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Antigravity returned invalid JSON:\n" + completed.stdout[-2000:]) from exc


def repair_with_antigravity(playbook: str, findings: list[dict[str, str]], deployment_error: str | None,
                            workspace: str, continue_session: bool) -> str:
    prompt = f"""You are an expert Ansible security engineer. Repair this Ansible playbook semantically.
Fix every ansible-lint and Checkov finding supplied below, and address any Docker/Ansible execution failure. Preserve the playbook's intended outcome and its task order unless a change is required for security or correctness. Do not silence checks with noqa, skip directives, or blanket suppressions. Do not invent unrelated tasks, credentials, images, variables, or roles. Ensure one fix does not break dependent tasks, variable references, handlers, module arguments, or idempotence.

Return the complete repaired playbook between these exact markers, with YAML only inside:
<REPAIRED_PLAYBOOK>
(complete playbook YAML)
</REPAIRED_PLAYBOOK>

Current scanner findings:
{json.dumps(findings, indent=2)}

Previous execution failure (empty before deployment fails):
{deployment_error or '(none)'}

Playbook:
```yaml
{playbook}
```"""
    response = antigravity_response(prompt, workspace, continue_session)
    try:
        return yaml_only(response)
    except ValueError as exc:
        raise ValueError(f"{exc}\nAntigravity response preview:\n{response.strip()[:1200]}") from exc


async def execute_playbook(directory: str, filename: str) -> tuple[bool, str]:
    # The supplied playbook runs against localhost inside this app container. Docker
    # modules use the mounted Docker socket to manage the configured Docker engine.
    code, output = await run_command(
        ["ansible-playbook", "-i", "localhost,", "--connection", "local", filename], directory
    )
    return code == 0, output


async def workflow(filename: str, source: str, progress) -> dict[str, Any]:
    current = source
    history: list[dict[str, Any]] = []
    deployment_error: str | None = None
    repair_started = False
    with tempfile.TemporaryDirectory(prefix="ansible-repair-") as workspace:
        path = Path(workspace) / filename
        for cycle in range(1, MAX_CYCLES + 1):
            path.write_text(current, encoding="utf-8")
            progress("scan", f"Cycle {cycle}/{MAX_CYCLES}: running ansible-lint.", cycle=cycle)
            lint_issues, checkov_issues = await scan_playbook(workspace, filename)
            progress("scan", f"Checkov found {len(checkov_issues)} finding(s).", issues=checkov_issues, cycle=cycle)
            progress("scan", f"ansible-lint found {len(lint_issues)} finding(s).", issues=lint_issues, cycle=cycle)
            findings = lint_issues + checkov_issues
            if findings or deployment_error:
                progress("repair", f"Cycle {cycle}/{MAX_CYCLES}: Antigravity is applying scanner findings.", cycle=cycle)
                current = await asyncio.to_thread(
                    repair_with_antigravity, current, findings, deployment_error, workspace, repair_started
                )
                repair_started = True
                path.write_text(current, encoding="utf-8")
                # Immediately rescan repaired output. It must be clean before Docker execution.
                progress("rescan", f"Cycle {cycle}/{MAX_CYCLES}: re-running ansible-lint and Checkov on the repaired playbook.", cycle=cycle)
                lint_issues, checkov_issues = await scan_playbook(workspace, filename)
                findings = lint_issues + checkov_issues
                progress("rescan", f"Rescan found {len(findings)} remaining finding(s).", issues=findings, cycle=cycle)
                if findings:
                    history.append({"cycle": cycle, "findings": findings, "execution_log": "Static checks still failed."})
                    deployment_error = "The repaired playbook still has these scanner findings: " + json.dumps(findings)
                    continue
            progress("deploy", f"Cycle {cycle}/{MAX_CYCLES}: executing playbook against Docker.", cycle=cycle)
            success, execution_log = await execute_playbook(workspace, filename)
            history.append({"cycle": cycle, "findings": [], "execution_log": execution_log})
            if success:
                progress("complete", f"Cycle {cycle} completed: checks passed and playbook executed successfully.", cycle=cycle)
                return {"success": True, "cycles": cycle, "playbook": current, "history": history}
            deployment_error = execution_log
            progress("repair", f"Cycle {cycle} execution failed; sending Docker/Ansible output to Antigravity.", cycle=cycle)
    progress("failed", "Playbook could not pass checks and execute within five cycles.")
    return {"success": False, "cycles": MAX_CYCLES, "playbook": current, "history": history,
            "message": "Could not produce a clean, successfully executed playbook in five cycles."}


async def run_job(job_id: str, filename: str, content: str) -> None:
    def progress(stage: str, message: str, issues: list[dict[str, str]] | None = None, cycle: int | None = None) -> None:
        event: dict[str, Any] = {"stage": stage, "message": message}
        if issues is not None:
            event["issues"] = issues
        if cycle is not None:
            event["cycle"] = cycle
        jobs[job_id]["events"].append(event)
    try:
        jobs[job_id]["result"] = await workflow(filename, content, progress)
        jobs[job_id]["status"] = "complete"
    except Exception as exc:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(exc)
        progress("error", str(exc))


@app.post("/api/playbooks")
async def upload_playbook(file: UploadFile = File(...)) -> dict[str, str]:
    filename = Path(file.filename or "playbook.yml").name
    if Path(filename).suffix.lower() not in {".yml", ".yaml"}:
        raise HTTPException(400, "Upload one .yml or .yaml Ansible playbook.")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Playbook exceeds the 500 KB upload limit.")
    try:
        content = raw.decode("utf-8")
        parsed = yaml.safe_load(content)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise HTTPException(400, f"Upload valid UTF-8 YAML: {exc}") from exc
    if not isinstance(parsed, list) or not parsed:
        raise HTTPException(400, "The uploaded YAML must be an Ansible playbook (a non-empty list of plays).")
    job_id = uuid.uuid4().hex
    jobs[job_id] = {"status": "running", "events": []}
    asyncio.create_task(run_job(job_id, filename, content))
    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str) -> dict[str, Any]:
    if job_id not in jobs:
        raise HTTPException(404, "Job not found.")
    return jobs[job_id]


@app.get("/api/jobs/{job_id}/download")
async def download_playbook(job_id: str):
    job = jobs.get(job_id)
    if not job or "result" not in job:
        raise HTTPException(404, "Repaired playbook is not ready.")
    directory = Path(tempfile.gettempdir()) / "ansible-repair-downloads"
    directory.mkdir(exist_ok=True)
    path = directory / f"repaired-{job_id}.yaml"
    path.write_text(job["result"]["playbook"], encoding="utf-8")
    return FileResponse(path, filename="repaired-playbook.yaml", media_type="application/x-yaml")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return Path(__file__).with_name("static.html").read_text(encoding="utf-8")

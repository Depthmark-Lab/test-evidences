"""Code quality gate: the SonarQube quality gate of the analysis of this exact commit.

Records the gate status as found. If SonarQube has not analysed this commit,
the fact cannot be established, so nothing is attached and the job reports an
error. Re-run once the analysis exists.
"""
from urllib.parse import quote

from evidence_sdk import basic_auth, commit, emit, env, get_json, param, unable

server = env("SONAR_URL").rstrip("/")
auth = basic_auth(env("SONAR_TOKEN"))
project, sha = param("sonar-project-key"), commit()

# Most recent 100 analyses of the project. The commit's analysis must be among them.
analyses = get_json(f"{server}/api/project_analyses/search?project={quote(project, safe='')}&ps=100", auth)
analysis = next((a["key"] for a in analyses.get("analyses", []) if a.get("revision") == sha), None)
if not analysis:
    unable(f"SonarQube has no analysis of commit {sha} for project {project}")

gate = get_json(f"{server}/api/qualitygates/project_status?analysisId={quote(analysis, safe='')}", auth)
status = gate["projectStatus"]["status"]

emit({
    "result": "pass" if status == "OK" else "fail",
    "server": server,
    "projectKey": project,
    "analysisId": analysis,
    "commit": sha,
    "status": status,
    "conditions": gate["projectStatus"].get("conditions", []),
})

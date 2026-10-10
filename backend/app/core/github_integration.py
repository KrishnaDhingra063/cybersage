import base64
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.models import Finding, FixSuggestion

logger = logging.getLogger(__name__)
settings = get_settings()


class GitHubError(Exception):
    """Raised when GitHub API operations fail."""
    pass


class GitHubIntegration:
    """
    Automates GitHub branch creation, file commits, and Pull Request orchestration
    for human-approved security remediations.
    """

    def __init__(self, token: Optional[str] = None):
        self.token = token or getattr(settings, "GITHUB_TOKEN", "")
        if not self.token:
            self.token = os.getenv("GITHUB_TOKEN", "")

    def _get_headers(self) -> Dict[str, str]:
        if not self.token:
            raise GitHubError("GITHUB_TOKEN is not configured in settings or environment.")
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PentestAI-Platform/1.0",
        }

    def open_remediation_pr(
        self,
        db: Session,
        fix_suggestion_id: str,
        owner_repo: Optional[str] = None,
        base_branch: Optional[str] = None,
        approver_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes complete PR creation pipeline and updates database records:
        1. Resolves fix suggestion and finding records.
        2. Queries base branch HEAD SHA.
        3. Creates a unique branch for the finding.
        4. Commits patched source code.
        5. Opens structured Pull Request with CVSS and reproduction details.
        6. Updates FixSuggestion state to 'applied'.
        """
        fix: Optional[FixSuggestion] = db.query(FixSuggestion).filter(
            FixSuggestion.id == fix_suggestion_id
        ).first()
        if not fix:
            raise GitHubError(f"FixSuggestion '{fix_suggestion_id}' not found.")

        finding: Optional[Finding] = db.query(Finding).filter(
            Finding.id == fix.finding_id
        ).first()
        if not finding:
            raise GitHubError(f"Associated Finding '{fix.finding_id}' not found.")

        repo = owner_repo or getattr(settings, "GITHUB_REPO", "")
        if not repo or "/" not in repo:
            raise GitHubError("Repository must be provided in 'owner/repo' format.")

        base = base_branch or getattr(settings, "GITHUB_BASE_BRANCH", "main")
        branch_name = self._generate_branch_name(finding.vuln_type, str(finding.id))
        commit_message = f"security: remediate {finding.vuln_type} in {fix.file_path}"
        pr_title = f"[Security] Fix {finding.vuln_type} in {os.path.basename(fix.file_path)}"
        pr_body = self._build_pr_markdown(finding, fix)

        base_url = f"https://api.github.com/repos/{repo}"
        headers = self._get_headers()

        with httpx.Client(base_url=base_url, headers=headers, timeout=45.0) as client:
            # 1. Resolve default branch if base not found
            default_branch = self._resolve_base_branch(client, base)

            # 2. Retrieve commit SHA for base branch
            base_sha = self._get_branch_head(client, default_branch)

            # 3. Create security branch off base SHA
            self._create_branch(client, branch_name, base_sha)

            # 4. Commit updated file contents
            new_commit_sha = self._commit_file(
                client=client,
                branch=branch_name,
                file_path=fix.file_path,
                content=fix.after_code,
                message=commit_message,
            )
            if not new_commit_sha:
                raise GitHubError("Commit operation failed to return a new SHA.")

            # 5. Open Pull Request
            pr_data = self._create_pull_request(
                client=client,
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=default_branch,
            )

        # 6. Synchronize state with persistence layer
        pr_url = pr_data.get("html_url", "")
        fix.pr_url = pr_url
        fix.status = "applied"
        fix.approved_by_user_id = approver_user_id
        fix.approved_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(fix)

        logger.info(f"Remediation PR opened successfully: {pr_url}")
        return {
            "pr_url": pr_url,
            "pr_number": pr_data.get("number"),
            "branch": branch_name,
            "base": default_branch,
            "status": "applied",
        }

    def create_pull_request(
        self,
        owner_repo: Optional[str],
        file_path: str,
        new_content: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
        base_branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generic PR creation used by API routes that already have their own
        commit message / PR title / PR body prepared (e.g. app/api/fixes.py).

        Unlike open_remediation_pr, this does NOT look up a FixSuggestion or
        Finding from the database — the caller supplies all content directly.
        Reuses the same low-level GitHub helpers as open_remediation_pr.
        """
        repo = owner_repo or getattr(settings, "GITHUB_REPO", "")
        if not repo or "/" not in repo:
            raise GitHubError("Repository must be provided in 'owner/repo' format.")

        base = base_branch or getattr(settings, "GITHUB_BASE_BRANCH", "main")
        branch_name = self._generate_branch_name_from_path(file_path)

        base_url = f"https://api.github.com/repos/{repo}"
        headers = self._get_headers()

        with httpx.Client(base_url=base_url, headers=headers, timeout=45.0) as client:
            # 1. Resolve default branch if base not found
            default_branch = self._resolve_base_branch(client, base)

            # 2. Retrieve commit SHA for base branch
            base_sha = self._get_branch_head(client, default_branch)

            # 3. Create branch off base SHA
            self._create_branch(client, branch_name, base_sha)

            # 4. Commit updated file contents
            new_commit_sha = self._commit_file(
                client=client,
                branch=branch_name,
                file_path=file_path,
                content=new_content,
                message=commit_message,
            )
            if not new_commit_sha:
                raise GitHubError("Commit operation failed to return a new SHA.")

            # 5. Open Pull Request
            pr_data = self._create_pull_request(
                client=client,
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=default_branch,
            )

        return {
            "pr_url": pr_data.get("html_url", ""),
            "pr_number": pr_data.get("number"),
            "branch": branch_name,
            "base": default_branch,
        }

    def _resolve_base_branch(self, client: httpx.Client, fallback_branch: str) -> str:
        resp = client.get("")
        if resp.status_code == 200:
            return resp.json().get("default_branch", fallback_branch)
        return fallback_branch

    def _get_branch_head(self, client: httpx.Client, branch: str, raise_missing: bool = True) -> str:
        resp = client.get(f"/git/ref/heads/{branch}")
        if resp.status_code == 200:
            return resp.json()["object"]["sha"]
        if raise_missing:
            raise GitHubError(f"Branch '{branch}' not found: {resp.text}")
        return ""

    def _create_branch(self, client: httpx.Client, branch: str, sha: str) -> None:
        # Idempotent branch creation check
        existing_sha = self._get_branch_head(client, branch, raise_missing=False)
        if existing_sha:
            return

        resp = client.post("/git/refs", json={
            "ref": f"refs/heads/{branch}",
            "sha": sha,
        })
        if resp.status_code not in (200, 201):
            raise GitHubError(f"Could not create branch '{branch}': {resp.text}")

    def _commit_file(
        self,
        client: httpx.Client,
        branch: str,
        file_path: str,
        content: str,
        message: str,
    ) -> str:
        path = urllib.parse.quote(file_path.strip().lstrip("/"), safe="/")
        existing_resp = client.get(f"/contents/{path}", params={"ref": branch})

        payload = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }

        if existing_resp.status_code == 200:
            payload["sha"] = existing_resp.json().get("sha")

        resp = client.put(f"/contents/{path}", json=payload)
        if resp.status_code in (200, 201):
            return resp.json()["commit"]["sha"]

        logger.error(f"GitHub commit failed: {resp.status_code} {resp.text}")
        raise GitHubError(f"File commit failed on path '{file_path}': {resp.text}")

    def _create_pull_request(
        self,
        client: httpx.Client,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> Dict[str, Any]:
        resp = client.post("/pulls", json={
            "title": title,
            "head": head,
            "base": base,
            "body": body,
        })
        if resp.status_code in (200, 201):
            return resp.json()
        raise GitHubError(f"Could not create PR: {resp.text}")

    @staticmethod
    def _generate_branch_name(vuln_type: str, finding_id: str) -> str:
        clean_vuln = re.sub(r"[^A-Za-z0-9_-]", "-", (vuln_type or "vuln")).lower()
        short_id = finding_id.replace("-", "")[:8]
        return f"security/fix-{clean_vuln}-{short_id}"

    @staticmethod
    def _generate_branch_name_from_path(file_path: str) -> str:
        clean = re.sub(r"[^A-Za-z0-9_-]", "-", os.path.basename(file_path or "fix")).lower().strip("-") or "fix"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"security/fix-{clean}-{ts}"

    @staticmethod
    def _build_pr_markdown(finding: Finding, fix: FixSuggestion) -> str:
        vuln_type = finding.vuln_type or "Unknown"
        severity = (finding.severity or "info").upper()
        cvss = finding.cvss_score or 0.0
        param = finding.parameter or "N/A"
        tool = finding.source_tool or "Autonomous Pentest Agent"
        desc = finding.description or "No description provided."
        explanation = fix.explanation or "No explanation provided."
        curl_cmd = fix.curl_replay or "# No reproduction command generated."
        waf_engine = fix.waf_engine or "nginx"
        waf_rule = fix.waf_rule or "# No WAF rule generated."

        body = (
            "## 🛡️ Autonomous Security Remediation\n\n"
            "### Vulnerability Summary\n"
            f"- **Vulnerability Type:** `{vuln_type}`\n"
            f"- **Severity:** **{severity}** (CVSS: `{cvss}`)\n"
            f"- **Target Endpoint/Parameter:** `{param}`\n"
            f"- **Detection Tool:** `{tool}`\n\n"
            "---\n\n"
            "### Technical Details & Explanation\n"
            f"{desc}\n\n"
            "**Remediation Rationale:**\n"
            f"{explanation}\n\n"
            "---\n\n"
            "### Reproduction & Verification\n"
            "To reproduce this finding pre-fix or verify the patch post-deployment:\n"
            f"```bash\n{curl_cmd}\n```\n\n"
            f"### Perimeter WAF Virtual Patch ({waf_engine})\n"
            f"```{waf_engine}\n{waf_rule}\n```\n\n"
            "---\n"
            "*Generated by Autonomous Pentesting Platform. Requires team approval prior to merge.*"
        )
        return body


def create_pull_request(
    owner_repo: Optional[str],
    file_path: str,
    new_content: str,
    commit_message: str,
    pr_title: str,
    pr_body: str,
    base_branch: Optional[str] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Module-level convenience wrapper so callers (e.g. app/api/fixes.py) can do:

        from app.core.github_integration import create_pull_request, GitHubError

    without having to instantiate GitHubIntegration themselves.
    """
    integration = GitHubIntegration(token=token)
    return integration.create_pull_request(
        owner_repo=owner_repo,
        file_path=file_path,
        new_content=new_content,
        commit_message=commit_message,
        pr_title=pr_title,
        pr_body=pr_body,
        base_branch=base_branch,
    )
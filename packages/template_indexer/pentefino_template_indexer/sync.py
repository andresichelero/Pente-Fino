import asyncio
import hashlib
from pathlib import Path
import shutil


class TemplateSyncError(Exception):
    """Raised when syncing Nuclei templates fails."""
    pass


class TemplateSyncManager:
    """
    Manages synchronization of upstream Nuclei templates repository.

    Supports:
    - Shallow cloning: git clone --depth 1
    - Fast-forward updates: git pull --ff-only
    - Upstream commit SHA pinning: git rev-parse HEAD
    - Offline and test-fixture local directory mode
    """

    def __init__(
        self,
        repo_url: str = "https://github.com/projectdiscovery/nuclei-templates.git",
        local_path: Path | str = Path("storage/templates/nuclei-templates"),
        custom_templates_dir: Path | str | None = None,
    ):
        self.repo_url = str(repo_url)
        self.local_path = Path(local_path).resolve()
        self.custom_templates_dir = (
            Path(custom_templates_dir).resolve() if custom_templates_dir else None
        )

    def get_templates_dir(self) -> Path:
        """Returns the active directory holding template files."""
        if self.custom_templates_dir and self.custom_templates_dir.is_dir():
            return self.custom_templates_dir
        return self.local_path

    async def sync(self) -> str:
        """
        Sync templates and return the immutable upstream commit SHA.

        In offline or test-fixture mode (custom_templates_dir set), returns
        the commit SHA or a deterministic synthetic revision.
        """
        target_dir = self.get_templates_dir()

        # Offline / custom fixtures directory
        if self.custom_templates_dir and self.custom_templates_dir.is_dir():
            return await self._get_revision(self.custom_templates_dir)

        # Ensure parent directory exists
        target_dir.parent.mkdir(parents=True, exist_ok=True)

        git_bin = shutil.which("git")
        if not git_bin:
            if target_dir.is_dir():
                return await self._get_revision(target_dir)
            raise TemplateSyncError("git executable not found on PATH and no local template cache exists")

        if not target_dir.exists() or not any(target_dir.iterdir()):
            # Clone shallow
            cmd = [git_bin, "clone", "--depth", "1", self.repo_url, str(target_dir)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise TemplateSyncError(
                    f"git clone failed with code {proc.returncode}: {stderr.decode(errors='replace')}"
                )
        else:
            # Pull updates if it is a git repo
            if (target_dir / ".git").is_dir():
                cmd = [git_bin, "-C", str(target_dir), "pull", "--ff-only"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                # If pull fails due to offline/network, we keep existing cache and extract HEAD
                if proc.returncode != 0:
                    pass

        return await self._get_revision(target_dir)

    async def _get_revision(self, directory: Path) -> str:
        """Extract Git commit SHA or compute synthetic revision."""
        git_bin = shutil.which("git")
        if git_bin and (directory / ".git").is_dir():
            try:
                proc = await asyncio.create_subprocess_exec(
                    git_bin,
                    "-C",
                    str(directory),
                    "rev-parse",
                    "HEAD",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    sha = stdout.decode().strip()
                    if sha:
                        return sha
            except Exception:
                pass

        # Fallback: compute deterministic hash of directory template files
        hasher = hashlib.sha256()
        yaml_files = sorted(list(directory.rglob("*.yaml")) + list(directory.rglob("*.yml")))
        if not yaml_files:
            return "0000000000000000000000000000000000000000"

        for yf in yaml_files:
            rel = yf.relative_to(directory).as_posix()
            hasher.update(rel.encode("utf-8"))
            try:
                hasher.update(yf.read_bytes())
            except Exception:
                pass

        return hasher.hexdigest()[:40]

    def list_template_files(self) -> list[Path]:
        """List all YAML template files in the templates directory."""
        directory = self.get_templates_dir()
        if not directory.is_dir():
            return []
        files: list[Path] = []
        for p in directory.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".yaml", ".yml"):
                # Ignore .git or internal files
                if ".git" not in p.parts:
                    files.append(p)
        return sorted(files)

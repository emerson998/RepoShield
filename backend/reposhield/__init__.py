"""RepoShield security triage."""
from importlib.metadata import PackageNotFoundError, version

# Single source of truth: backend/pyproject.toml.
try:
    __version__ = version("reposhield")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

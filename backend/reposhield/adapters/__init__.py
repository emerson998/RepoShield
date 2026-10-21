"""External tool adapters registry. Order is the execution order of 'auto'."""
from .gitleaks import Gitleaks
from .osv_scanner import OsvScanner
from .semgrep import Semgrep
from .trivy import Trivy
from .zap import ZapBaseline

ADAPTERS = [Gitleaks(), OsvScanner(), Semgrep(), Trivy(), ZapBaseline()]
NAMES = {adapter.name for adapter in ADAPTERS}

"""Log-analysis adapters for CI and deployment streams."""

from ._normalize import LogAnalysisAdapter, envelope, iter_clean_lines, make_event
from .cd_deployment import (
    SystemdDeploymentLogAdapter,
    analyze_systemd_deploy_log,
    iter_systemd_deploy_events,
)
from .ci_github_actions import (
    GitHubActionsLogAdapter,
    analyze_github_actions_log,
    iter_github_actions_events,
)

__all__ = [
    "GitHubActionsLogAdapter",
    "LogAnalysisAdapter",
    "SystemdDeploymentLogAdapter",
    "analyze_github_actions_log",
    "analyze_systemd_deploy_log",
    "envelope",
    "iter_clean_lines",
    "iter_github_actions_events",
    "iter_systemd_deploy_events",
    "make_event",
]

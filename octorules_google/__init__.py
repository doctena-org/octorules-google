"""Google Cloud Armor provider for octorules."""

from octorules.phases import register_api_fields, register_phases

from octorules_google.linter import register_google_linter
from octorules_google.provider import _GCLOUD_PHASES, CloudArmorProvider
from octorules_google.validate import validate_rules

GCLOUD_PHASE_NAMES: frozenset[str] = frozenset(p.friendly_name for p in _GCLOUD_PHASES)

register_phases(_GCLOUD_PHASES)
register_api_fields("rule", {"kind", "preview"})
register_google_linter()

# Register audit IP extractor.
from octorules_google.audit import register_google_audit  # noqa: E402

register_google_audit()

__all__ = ["CloudArmorProvider", "validate_rules"]

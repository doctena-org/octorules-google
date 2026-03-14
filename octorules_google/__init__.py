"""Google Cloud Armor provider for octorules."""

from octorules.phases import Phase, register_api_fields, register_phases

from octorules_google.linter import register_google_linter
from octorules_google.provider import CloudArmorProvider
from octorules_google.validate import validate_rules

_GCLOUD_PHASES = [
    Phase(
        "gcloud_armor_custom_rules",
        "gcloud_armor_custom",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "gcloud_armor_rate_rules",
        "gcloud_armor_rate",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "gcloud_armor_preconfigured_rules",
        "gcloud_armor_preconfigured",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "gcloud_armor_redirect_rules",
        "gcloud_armor_redirect",
        None,
        zone_level=True,
        account_level=False,
    ),
]

register_phases(_GCLOUD_PHASES)
register_api_fields("rule", {"kind", "preview"})
register_google_linter()

__all__ = ["CloudArmorProvider", "validate_rules"]

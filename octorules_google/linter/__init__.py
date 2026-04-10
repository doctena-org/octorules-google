"""Google Cloud Armor linter — registers all GCloud-specific lint rules and plugins."""

import threading

_registered = False
_register_lock = threading.Lock()


def register_google_linter() -> None:
    """Register the Google Cloud Armor lint plugin and rule definitions.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _registered
    with _register_lock:
        if _registered:
            return

        from octorules.linter.plugin import LintPlugin, register_linter
        from octorules.linter.rules.registry import register_rules

        from octorules_google.linter._plugin import GA_RULE_IDS, google_lint
        from octorules_google.linter._rules import GA_RULE_METAS

        register_linter(LintPlugin(name="google", lint_fn=google_lint, rule_ids=GA_RULE_IDS))
        register_rules(GA_RULE_METAS)

        _registered = True

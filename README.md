# octorules-google

Google Cloud Armor provider for [octorules](https://github.com/doctena-org/octorules) — manages Cloud Armor security policy rules as YAML.

## Installation

```bash
pip install octorules-google
```

This installs octorules (core), octorules-google, and
[cel-python](https://pypi.org/project/cel-python/) for CEL expression
validation in the linter. The provider is auto-discovered — no `class:` needed
in config.

## Configuration

```yaml
providers:
  google:
    project: my-gcp-project
  rules:
    directory: ./rules

zones:
  my-security-policy:
    sources:
      - rules
```

Each zone name maps to a Cloud Armor security policy name. The provider
resolves policy names at runtime.

### Authentication

Authentication uses
[Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
— no token is needed in the config file. Common options:

- **`gcloud auth application-default login`** — for local development
- **Service account key**: set `GOOGLE_APPLICATION_CREDENTIALS` to the JSON key path
- **Workload Identity** (GKE, Cloud Run): automatic

Required IAM permissions:

- `compute.securityPolicies.get`, `compute.securityPolicies.update` — for rule operations
- `compute.securityPolicies.list` — for zone discovery
- `compute.securityPolicies.addRule`, `compute.securityPolicies.removeRule` — for rule changes

### Provider settings

All settings below go under the provider section (e.g. `providers.google`).

| Key | Default | Description |
|-----|---------|-------------|
| `project` | `GCLOUD_PROJECT` env var | GCP project ID (required) |
| `timeout` | `30` | API timeout in seconds |

Safety thresholds are configured under `safety:` (framework-owned, not forwarded to the provider):

| Key | Default | Description |
|-----|---------|-------------|
| `safety.delete_threshold` | `30.0` | Max % of rules that can be deleted |
| `safety.update_threshold` | `30.0` | Max % of rules that can be updated |
| `safety.min_existing` | `3` | Min rules before thresholds apply |

## Supported features

| Feature | Status | Notes |
|---------|--------|-------|
| Phase rules (4 phases) | Supported | Security policy rules |
| Policy settings | Supported | Adaptive protection, DDoS config, default rule action |
| Custom rulesets | Not supported | — |
| Lists | Not supported | Use inline IP ranges in match config |
| Page Shield | Not supported | — |
| Zone discovery (`list_zones`) | Supported | Lists security policies |
| Account-level scopes | Not supported | — |
| Audit IP extraction (`octorules audit`) | Supported | `src_ip_ranges` + `inIpRange()` CEL |

## Phase mapping

| octorules phase | Cloud Armor concept |
|---|---|
| `gcloud_armor_custom_rules` | Custom rules (IP match, geo match, CEL expressions) |
| `gcloud_armor_rate_rules` | Rate-limiting rules (throttle / rate_based_ban) |
| `gcloud_armor_preconfigured_rules` | Preconfigured WAF rules (OWASP ModSecurity, etc.) |
| `gcloud_armor_redirect_rules` | Redirect rules (302 response) |

Rules are identified by their integer **priority** (mapped to `ref` in octorules). All phases require `action` to be specified explicitly (no default action).

## Rule format

Cloud Armor rules use a different structure from other providers. The `ref` field maps to the rule's integer priority:

```yaml
# rules/my-security-policy.yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    description: "Block known bad IPs"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "1.2.3.4/32"
          - "5.6.7.0/24"

  - ref: "2000"
    description: "Rate limit API endpoints"
    action: throttle
    match:
      expr:
        expression: "request.path.startsWith('/api/')"
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      rate_limit_threshold:
        count: 100
        interval_sec: 60

gcloud_armor_preconfigured_rules:
  - ref: "3000"
    description: "OWASP SQL injection protection"
    action: deny(403)
    match:
      expr:
        expression: "evaluatePreconfiguredWaf('sqli-v33-stable')"
```

### CEL expressions

Cloud Armor uses [CEL (Common Expression Language)](https://cloud.google.com/armor/docs/rules-language-reference) for advanced match expressions. Examples:

```yaml
# IP-based matching
match:
  expr:
    expression: "inIpRange(origin.ip, '10.0.0.0/8')"

# Header matching
match:
  expr:
    expression: "request.headers['user-agent'].contains('BadBot')"

# Geo-based matching
match:
  expr:
    expression: "origin.region_code == 'US'"
```

> **Rule-level metadata:** All Cloud Armor rules support the `octorules:` key for per-rule metadata — `ignored: true` to skip a rule during plan/sync, and `included`/`excluded` to restrict rules to specific providers. See [octorules core docs](https://github.com/doctena-org/octorules#rule-level-metadata) for syntax and examples.

## Linting

77 Cloud Armor-specific lint rules (GA prefix) covering structure, expressions, actions, rate limiting, redirects, sub-structure validation, and cross-rule analysis:

| Prefix | Category | Rules |
|--------|----------|-------|
| GA001-GA006, GA020 | Structure | 7 |
| GA100-GA108 | Priority / cross-rule | 7 |
| GA200-GA201 | Action | 2 |
| GA300-GA327 | Match / expression / CEL / sub-structure | 22 |
| GA400-GA433 | Rate limit / redirect / action params | 32 |
| GA500-GA503 | Best practice | 4 |
| GA600-GA602 | Preview / catch-all | 3 |

```bash
octorules lint --config config.yaml
```

Lint rules are registered automatically when octorules-google is installed. CEL expression validation uses [cel-python](https://pypi.org/project/cel-python/). See [docs/lint.md](docs/lint.md) for the full rule reference with examples.

## Known limitations

- **Non-atomic updates:** Cloud Armor does not support atomic bulk rule replacement. `put_phase_rules` patches existing rules in place, adds new rules, then removes stale rules — so the policy never has *fewer* rules than intended. Each API call is retried for transient errors with exponential backoff. If an operation fails after retries, partial progress is logged and the next sync will reconcile.
- **Policy creation/deletion:** octorules-google manages rules within existing security policies. Creating or deleting policies (and attaching them to backend services) should be done via `gcloud` or Terraform.
- **Policy settings require the extension.** Policy-level settings (`adaptive_protection_config`, `advanced_options_config`, `ddos_protection_config`, `default_rule_action`, `recaptcha_options_config`) are managed via the `gcloud_armor_policy_settings` extension. Without the extension enabled, these settings should be managed via `gcloud` or Terraform.

> **Note:** Per-rule rate limiting fields (`enforceOnKey`, `enforceOnKeyConfigs`, `banDurationSec`), header actions (`headerAction`), and CEL functions like `evaluateJsonPath()` are already supported — they pass through as-is in the rule dict.

## Development

```bash
git clone git@github.com:doctena-org/octorules-google.git
cd octorules-google
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

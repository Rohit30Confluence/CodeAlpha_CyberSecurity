# Secure Coding Review Report

## Scope

The review tool examines Python abstract syntax trees for `eval`, `exec`, `pickle.loads`, and subprocess calls with `shell=True`. It identifies the line, severity, rationale, and remediation without executing the target file.

## Severity model

| Rule | Severity | Risk | Recommended remediation |
| --- | --- | --- | --- |
| S001 | High | `eval` may execute attacker-controlled expressions | Replace with a typed parser or allowlisted mapping. |
| S002 | High | `exec` enables arbitrary code execution | Replace with explicit code paths. |
| S003 | High | Pickle can invoke code while deserialising | Use JSON plus schema validation for untrusted data. |
| S004 | Medium | Shell execution can enable injection | Use argument arrays, validation, and `shell=False`. |

## Review limitations

This is a focused educational static check. It does not perform data-flow analysis, dependency scanning, secret detection, or runtime testing. Findings should be triaged by a developer before remediation is prioritised.

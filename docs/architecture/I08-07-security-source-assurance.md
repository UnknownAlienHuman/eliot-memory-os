## I8.7. Security Source Assurance

Watchdog records independently observable security features and deterministic risk flags. Optional Watchdog Agents may propose a semantic risk assessment as candidate-only output. Governor stores the governed profile with both sources separated; model confidence alone cannot create quarantine, Incident or authority change.

```yaml
SourceSecurityAssessment:
  source_ref:
  identity_assurance:
  integrity_assurance:
  instruction_injection_risk:
  deception_risk:
  exfiltration_risk:
  persistence_risk:
  suspicious_patterns:
  affected_capabilities:
  suggested_quarantine:
  required_probe:
  confidence_and_limits:
```

It does not decide semantic truth.


## New Detector: [detector-name]

### What it detects

[Brief description of the anomaly or threat this detector identifies]

### Severity

[info | warn | critical]

### Sources

[Which connectors provide relevant events (e.g., azure, github, m365)]

### Why it matters

[Explanation of why this detection is important for security monitoring]

### False positives

[Known cases where the detector might fire incorrectly, and how to tune it]

### Checklist

- [ ] `manifest.yaml` present with all required fields (`name`, `description`, `version`, `sources`, `event_types`, `severity_default`)
- [ ] `detector.py` implements `DetectorBase` or detector uses DeclarativeDetector YAML format
- [ ] `mallcop verify detectors/<name>` passes
- [ ] Full test suite passes (`pytest`)
- [ ] New unit tests added for the detector logic
- [ ] Description explains what the detector catches and why it matters

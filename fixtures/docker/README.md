# Docker Misconfiguration Fixture

## Expected Detections
- VBG-DEP-001: USER root directive configured
- VBG-DEP-002: Floating :latest base image tag used
- VBG-DEP-003: Environment secret file (.env) copied into container image
- VBG-DEP-004: Missing HEALTHCHECK instruction

## Should NOT Detect
- Valid application runtime code errors

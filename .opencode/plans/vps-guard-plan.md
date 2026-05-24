# VPS-Guard Implementation Plan

## Project Structure
See full architecture in README.

## Phase 1: Go Scaffold + Entry Point
- go.mod with dependencies
- Makefile with build/install/test targets
- cmd/vps-guard/main.go: main entry point

## Phase 2: Config + Event Model + Pipeline
- internal/config/config.go: YAML config loading
- internal/pipeline/event.go: Event interface + Envelope
- internal/pipeline/bus.go: Channel-based event bus
- internal/pipeline/stages.go: Multi-stage pipeline

## Phase 3: Monitor
- internal/monitor/journal.go: systemd journal reader
- internal/monitor/parser.go: SSH log regex parser
- internal/monitor/behavioral.go: Local scoring (frequency, window, usernames)

## Phase 4: Threat Intel
- internal/threat/abuseipdb.go: AbuseIPDB API client
- internal/threat/alienvault.go: AlienVault OTX client
- internal/threat/client.go: Combined async client
- internal/threat/cache.go: SQLite cache with TTL

## Phase 5: Engine + Rules
- internal/engine/scorer.go: Weighted scoring (AbuseIPDB+OTX+Behavioral+Temporal)
- internal/engine/decision.go: Decision engine
- internal/engine/memory.go: Temporal reputation memory
- internal/rules/engine.go: YAML rules engine
- internal/rules/rules.yaml: Default rules

## Phase 6: Firewall + Notify
- internal/firewall/nftables.go: nftables dynamic sets
- internal/notify/telegram.go: Telegram bot
- internal/notify/email.go: SMTP email
- internal/notify/notifier.go: Combined notifier

## Phase 7: Bootstrap + Deploy
- internal/bootstrap/hardening.go: System hardening
- internal/selfprotect/watchdog.go: Watchdog
- deploy/install.sh: One-command installer
- deploy/vps-guard.service: systemd unit
- config.yaml: Default configuration

## Phase 8: Documentation
- docs/ARCHITECTURE.md
- docs/THREAT_MODEL.md
- docs/RFC-0001-event-model.md

## Scoring Formula
FinalScore = (AbuseIPDB × 0.30) + (OTX × 0.25) + (Behavioral × 0.30) + (Temporal × 0.15)

80-100: Critical → Block 24h + Notify
50-79:  High    → Block 24h + Notify
25-49:  Medium  → Quarantine 15m + Notify
1-24:   Low     → Monitor only
0:      Clean   → Ignore

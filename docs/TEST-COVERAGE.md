# vpsGuard — Test Coverage Report

**Version**: 0.2.0  
**Last Updated**: 2026-05-26  
**Total test files**: 19  
**Total test functions**: 136  
**Build**: `go build ./...` ✅  
**Vet**: `go vet ./...` ✅  
**Tests**: `go test ./...` ✅ (all 11 packages pass)

---

## Summary by Package

| Package | Test File | Tests | Coverage Area |
|---------|-----------|-------|---------------|
| `internal/api` | `health_test.go` | 4 | HTTP server start/stop, responses, degraded mode |
| `internal/api` | `pull_client_test.go` | 6 | Feed fetching, auth, confidence filtering, malformed JSON |
| `internal/bootstrap` | `hardening_test.go` | 7 | Config file manipulation, kernel param content |
| `internal/config` | `config_test.go` | 3 | Defaults, validation, YAML loading |
| `internal/engine` | `audit_test.go` | 2 | Audit logging, multiple entries |
| `internal/engine` | `decision_test.go` | 5 | Block/monitor/rate-limit/central feed decisions |
| `internal/engine` | `memory_test.go` | 13 | Reputation storage, scoring, cleanup, concurrency |
| `internal/engine` | `pipeline_test.go` | 10 | End-to-end: record → score → decide → act |
| `internal/engine` | `scorer_test.go` | 4 | Scoring, verdict, event recording |
| `internal/firewall` | `nftables_test.go` | 3 | Manager init, block/unblock, contains-IP |
| `internal/firewall` | `persist_test.go` | 6 | Block store save/load, expiry, cleanup |
| `internal/monitor` | `behavioral_test.go` | 15 | Behavioral analysis, window scoring, concurrency |
| `internal/monitor` | `parser_test.go` | 3 | SSH log parsing, event conversion |
| `internal/notify` | `notifier_test.go` | 11 | Telegram/email formatting, cooldown logic |
| `internal/pipeline` | `bus_test.go` | 10 | Event bus subscribe/publish/fan-out/context |
| `internal/rules` | `engine_test.go` | 11 | Rule matching, numeric/string conditions, YAML loading |
| `internal/selfprotect` | `watchdog_test.go` | 9 | Watchdog ping/uptime, checksum match/mismatch |
| `internal/threat` | `alienvault_test.go` | 3 | OTX pulse scoring, client creation |
| `internal/threat` | `cache_test.go` | 11 | IP cache get/set/expiry/cleanup, central score |

**Total**: 19 files · 136 test functions · 11 packages

---

## Detailed Test Listing

### `internal/api/health_test.go` (4 tests)
- `TestHealthServerStartStop` — server starts and stops cleanly
- `TestHealthServerResponse` — `/health` returns 200 with status
- `TestHealthServerMethodNotAllowed` — non-GET returns 405
- `TestHealthServerDegraded` — degraded mode returns 503

### `internal/api/pull_client_test.go` (6 tests)
- `TestNewPullClient` — client creation with config
- `TestFetchFeed` — fetches and parses feed items
- `TestFetchFeedUnauthorized` — 401 returns error
- `TestPullWithMinConfidence` — filters by confidence threshold
- `TestStartDisabled` — disabled feed returns nil
- `TestFeedMalformedJSON` — handles bad JSON gracefully

### `internal/bootstrap/hardening_test.go` (7 tests)
- `TestSetConfigValueAddsNewKey` — adds new SSH config key
- `TestSetConfigValueUpdatesExisting` — updates existing value
- `TestSetConfigValueMultipleLines` — handles multi-line files
- `TestSetConfigValuePreservesOtherLines` — doesn't corrupt unrelated lines
- `TestSetConfigValueEmptyContent` — handles empty files
- `TestSetConfigValueHandlesSpaces` — handles whitespace
- `TestKernelParamsContent` — verifies kernel hardening params

### `internal/config/config_test.go` (3 tests)
- `TestSetDefaults` — defaults applied for empty config
- `TestValidate` — validation passes for valid config
- `TestLoad` — loads and parses YAML file

### `internal/engine/audit_test.go` (2 tests)
- `TestAuditLoggerLog` — audit entry is recorded correctly
- `TestAuditLoggerMultipleEntries` — multiple entries are sequential

### `internal/engine/decision_test.go` (5 tests)
- `TestDecisionEvaluateBlock` — score ≥ threshold blocks
- `TestDecisionEvaluateMonitor` — low score monitors
- `TestDecisionEvaluateRateLimit` — rate-limit threshold triggers correctly
- `TestDecisionEvaluateRateLimitBelowThreshold` — below threshold no action
- `TestDecisionEvaluateCentralFeed` — central feed override works

### `internal/engine/memory_test.go` (13 tests)
- `TestNewReputationMemory` — creates with valid TTL
- `TestReputationMemoryRecord` — records IP events
- `TestReputationMemoryRecordMultiple` — multiple events accumulate
- `TestReputationMemoryMaxHistory` — respects max history limit
- `TestReputationMemoryRecordDifferentIPs` — separate tracking per IP
- `TestReputationMemoryGetScoreEmpty` — empty memory returns 0
- `TestReputationMemoryGetScoreByCount` — score increases with event count
- `TestReputationMemoryGetScoreWithHighAverage` — high avg score adds bonus
- `TestReputationMemoryGetScoreCombined` — count + avg combined
- `TestReputationMemoryCleanup` — expired entries are removed
- `TestReputationMemoryCleanupKeepsRecent` — recent entries survive cleanup
- `TestReputationMemoryAutoCleanupGetScore` — GetScore triggers cleanup
- `TestReputationMemoryConcurrentSafe` — safe under concurrent access

### `internal/engine/pipeline_test.go` (10 tests)
- `TestPipelineRecordThenEvaluateAndDecide` — full pipeline flow
- `TestPipelineScoreCrossesBlockThreshold` — high score → block
- `TestPipelineQuarantineThreshold` — medium score → quarantine
- `TestPipelineMonitorOnly` — low score → monitor
- `TestPipelineCleanSlateNoAction` — no events → no action
- `TestPipelineCentralFeedBlock` — central feed triggers block
- `TestPipelineCentralFeedQuarantine` — central feed triggers quarantine
- `TestPipelineRuleEngineMatch` — rules override thresholds
- `TestPipelineScorerBehavioralAccumulation` — behavioral scores accumulate
- `TestPipelineCleanup` — temporal memory cleanup works end-to-end

### `internal/engine/scorer_test.go` (4 tests)
- `TestScoreResultVerdict` — verdict string formatting
- `TestNewScorer` — creates with config
- `TestScorerEvaluateNoIntel` — no external intel → behavioral only
- `TestScorerRecordEvent` — records behavioral event

### `internal/firewall/nftables_test.go` (3 tests)
- `TestNewNftables` — manager creation
- `TestBlockUnblockIP` — block and unblock cycle
- `TestContainsIP` — IP membership check (*requires root for full test*)

### `internal/firewall/persist_test.go` (6 tests)
- `TestBlockStoreSaveAndLoad` — persist and restore blocks
- `TestBlockStoreLoadExpired` — expired blocks not restored
- `TestBlockStoreLoadNonExistent` — missing file handled gracefully
- `TestBlockStoreRemove` — remove persisted block
- `TestBlockStoreCleanup` — expired block cleanup
- `TestBlockStoreMultipleSaves` — multiple IPs persisted and restored

### `internal/monitor/behavioral_test.go` (15 tests)
- `TestNewBehavioralAnalyzer` — creates with configurable window
- `TestBehavioralGetScoreUnknownIP` — unknown IP returns 0
- `TestBehavioralRecordAndGetScore` — record increases score
- `TestBehavioralScoreThreshold` — attempts ≥ threshold scores
- `TestBehavioralScoreAboveThreshold` — attempts ≥ 3× threshold scores more
- `TestBehavioralMultipleUsernames` — unique usernames bonus
- `TestBehavioralMultiplePorts` — unique ports bonus
- `TestBehavioralWindowScoring` — window-based scoring
- `TestBehavioralWindowExpiry` — old events decay
- `TestBehavioralCleanup` — cleanup removes old entries
- `TestBehavioralCleanupKeepsRecent` — recent entries survive cleanup
- `TestBehavioralConcurrentSafe` — safe under concurrent access
- `TestBehavioralMultipleIPs` — separate tracking per IP
- `TestBehavioralCleanupEmpty` — empty analyzer cleans up safely
- `TestBehavioralIPRecordFields` — record fields correctly populated

### `internal/monitor/parser_test.go` (3 tests)
- `TestParserParse` — parses SSH log lines correctly (10 sub-cases)
- `TestToEvent` — converts parsed entry to pipeline event
- `TestBehavioralAnalyzerFromParser` — parser feeds behavioral analyzer

### `internal/notify/notifier_test.go` (11 tests)
- `TestNewNotifierEmpty` — notifier with no channels
- `TestNewNotifierTelegramOnly` — telegram-only notifier
- `TestNewNotifierEmailOnly` — email-only notifier
- `TestFormatAlertAllVerdicts` — all verdict types formatted
- `TestFormatAlertActionTypes` — action types correct text
- `TestFormatAlertScoreBreakdown` — score breakdown in alert
- `TestSendWithNoNotifiers` — no panic with empty notifier
- `TestCooldownBlocksDuplicate` — cooldown prevents duplicate alerts
- `TestCooldownDifferentIPs` — different IPs not blocked
- `TestCooldownExpires` — cooldown expiry allows re-notify
- `TestNewNotifierCooldownConfig` — configurable cooldown

### `internal/pipeline/bus_test.go` (10 tests)
- `TestNewBus` — creates event bus
- `TestSubscribe` — subscriber receives events
- `TestPublish` — publish delivers to subscriber
- `TestPublishMultipleListeners` — fan-out to multiple subscribers
- `TestPublishContextCancel` — context cancel stops publish
- `TestFanOut` — parallel delivery to subscribers
- `TestEnvelopeSourceIP` — envelope fields correctly set
- `TestEventTypes` — all event types defined
- `TestPriorityConstants` — priority constants ordered
- `TestEventTypeConstants` — event type strings match expected

### `internal/rules/engine_test.go` (11 tests)
- `TestEngineDefaults` — default rules loaded
- `TestEvaluateMatch` — matching rule triggers
- `TestEvaluateNoMatch` — no match → no action
- `TestEvaluateNumericConditions` — numeric comparisons (`>`, `<`, `==`, `>=`, `<=`)
- `TestEvaluateWindowCondition` — time window conditions
- `TestCompareNumeric` — numeric comparison function
- `TestCompareNumericInvalid` — invalid comparison handled
- `TestGetFieldValue` — field extraction from event
- `TestLoadFromYAML` — YAML rule loading
- `TestInvalidYAML` — invalid YAML returns error
- `TestDefaultRulesTimestamp` — default rules have timestamp

### `internal/selfprotect/watchdog_test.go` (9 tests)
- `TestNewWatchdog` — creates with config path
- `TestWatchdogPing` — ping updates timestamp
- `TestWatchdogUptime` — uptime increases
- `TestWatchdogTickCount` — ticks increment
- `TestWatchdogChecksumEmpty` — empty checksum → no error
- `TestWatchdogChecksumMatch` — matching checksum → OK
- `TestWatchdogChecksumMismatch` — mismatch → warning
- `TestWatchdogChecksumConsecutiveWarnings` — multiple mismatches
- `TestWatchdogChecksumMatchResetsCounter` — match resets warning count

### `internal/threat/alienvault_test.go` (3 tests)
- `TestOTXPulseToScore` — pulse count → score mapping
- `TestNewAlienVaultClient` — OTX client creation
- `TestNewAbuseIPDBClient` — AbuseIPDB client creation

### `internal/threat/cache_test.go` (11 tests)
- `TestNewIPCache` — creates cache
- `TestIPCacheGetSet` — basic get/set
- `TestIPCacheOverwrite` — overwrite updates entry
- `TestIPCacheIsExpired` — TTL expiry detection
- `TestIPCacheCleanup` — removes expired entries
- `TestIPCacheSetOverwritesTTL` — set resets TTL
- `TestNewIntelClient` — client creation with empty keys
- `TestIntelClientWithKeys` — client creation with API keys
- `TestSetCentralScoreNew` — central score on new entry
- `TestSetCentralScoreUpdate` — central score updates existing
- `TestCacheCleanup` — full cache cleanup cycle

---

## CI Pipeline

The project uses GitHub Actions with two workflows:

### `ci.yml`
- `go vet ./...` — static analysis
- `go test -v -count=1 -race ./...` — race detection tests
- `go build -ldflags="-s -w" -o vpsGuard ./cmd/vpsGuard/` — build
- `./vpsGuard -version` — version check
- `ls -lh vpsGuard` — binary size check
- Cross-compile for amd64/arm64/arm

### `release.yml`
- Tests + race detection
- Cross-compile + checksums
- GitHub release with binary upload

---

## Running Tests Locally

```bash
# All tests
go test ./...

# With race detection
go test -race ./...

# Verbose output
go test -v ./...

# Specific package
go test -v ./internal/engine/...

# Coverage
go test -coverprofile=profile.cov ./...
go tool cover -html=profile.cov -o coverage.html
```

**Note**: `nftables_test.go` requires root for full nftables operations.
Without root, these tests are skipped gracefully.

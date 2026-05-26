# vpsGuard: خطة v0.3.0 — Hardening + Reporting + Uninstall

## ✅ منجز (I1–I5)

| البند | الحالة |
|-------|--------|
| I1 — SHA256 verification في install.sh | ✅ |
| I2 — Event bus buffer 1000→10000 + drop counter | ✅ |
| I3 — IP Whitelist (config + decision engine) | ✅ |
| I4 — IPv6 dual-stack nftables (بلاستليست 6) | ✅ |
| I5 — توحيد اسم binary في Makefile + paths | ✅ |

---

## 🔴 الخطة الجديدة — v0.3.0 ✅

### H1: --uninstall في install.sh ✅
### H2: deploy/harden.sh ✅
### H3: Log Lifecycle + Hash Chain ✅
### H4: Daily Telegram Report ✅

- `internal/reporting/reporter.go` — DailyReporter
- Timer كل 24 ساعة
- يجمع: system health (CPU/RAM/disk)، إحصائيات الحجب (24h)، audit events، hash chain integrity، التحديثات
- يرسل عبر Telegram notifier الموجود بدون معلومات حساسة
- قسم `daily_report:` في config.yaml

---

## خريطة الطريق

| المرحلة | البنود |
|---------|--------|
| v0.3.0-alpha | I1–I5 (منجز) |
| v0.3.0-beta  | H1 (uninstall) + H2 (harden.sh) |
| v0.3.0       | H3 (hash chain) + H4 (daily report) |

## ✅ تم إنجازه سابقاً (S1–S10)

| الكود | التحسين | الحالة |
|-------|---------|--------|
| S1 | Parser: tailFile بدل os.ReadFile | ✅ |
| S2 | SetCentralScore: دمج بدل مسح | ✅ |
| S3 | journal.go: context leak fix | ✅ |
| S4 | Rate limit guard (panic fix) | ✅ |
| S5 | nftables netlink (جزئي) | ✅ |
| S6 | Cleanup + LoadFromYAML في main.go | ✅ |
| S7 | Config validation | ✅ |
| S8 | Temporal memory: Final Score | ✅ |
| S9 | Log rotation (lumberjack) | ✅ |
| S10 | Unit Tests (19 ملف، 136 اختبار) | ✅ |

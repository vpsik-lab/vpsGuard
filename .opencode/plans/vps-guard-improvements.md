# VPS-Guard: خطة التحسين والإصلاح v2

## 🔴 المرحلة 1 — إصلاحات حرجة (v0.1.1)
_5 ملفات — مشاكل أداء + استقرار_

### S1: `monitor/parser.go` — tailFile يستخدم seek/tail
**المشكلة**: `os.ReadFile(path)` يقرأ الملف كاملاً كل 5 ثوانٍ
**الحل**: تخزين `os.File` مفتوح + `file.Seek(0, 2)` + قراءة new lines فقط
**التأثير**: من قراءة عدة GB → قراءة بضعة KB كل دقيقة

### S2: `threat/client.go` — SetCentralScore يدمج بدل يمسح
**المشكلة**: `SetCentralScore()` ينشئ CacheEntry جديد بدون AbuseIPDB/OTX scores
**الحل**: قراءة cache الموجود أولاً ثم إضافة CentralScore

### S3: `monitor/journal.go` — context leak
**المشكلة**: `m.bus.Publish(context.Background(), env)` بدل ctx
**الحل**: تمرير ctx من Run() إلى poll()

### S4: `threat/client.go:38` — Rate limit guard
**المشكلة**: `time.Second / time.Duration(RateLimit)` → panic عند RateLimit=0
**الحل**: guard + minimum value (if <=0 → 1)

### S5: `firewall/nftables.go` — netlink بدل exec.Command
**المشكلة**: كل `BlockIP()` يولد process جديد → overhead
**الحل**: استخدام `github.com/google/nftables` library (netlink مباشر)
**التأثير**: من 1-5ms → < 100µs لكل حظر

## 🟡 المرحلة 2 — تحسينات متوسطة (v0.2.0)

### S6: ربط Cleanup + LoadFromYAML في main.go
- Cleanup ticker كل ساعة (behavioral + memory + cache)
- تحميل rules.yaml لو موجود

### S7: Config validation
- Validate() -> error عند القيم غير المنطقية
- Defaults للقيم الفارغة

### S8: Temporal memory يسجل Final Score (بدل Behavioral)
```go
s.memory.Record(ip, result.FinalScore)  // ← بدل result.Behavioral
```

### S9: Log rotation (lumberjack)
- MaxSize 100MB, MaxBackups 3, MaxAge 7 days

### S10: Unit Tests (6 packages)
- parser_test.go, scorer_test.go, decision_test.go
- nftables_test.go, rules_test.go, config_test.go

## 🔵 المرحلة 3 — تنظيف

### S11: تحسينات بسيطة
- إزالة dead code (stages.go struct)
- توحيد generateID()
- mkdir تلقائي للـ cache/log
- fix tab spacing في notifier.go

## خريطة الطريق

| المرحلة | الوقت | الملفات |
|---------|-------|---------|
| v0.1.1 (حرجة) | ~3 ساعات | 5 ملفات |
| v0.2.0 (تحسينات) | ~5 ساعات | 10+ ملفات |

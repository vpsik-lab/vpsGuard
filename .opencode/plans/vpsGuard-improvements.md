# vpsGuard: خطة التحسينات القادمة — v0.3.0

بناءً على تقييم المراجعة الخارجية + التحليل الداخلي. كل البنود **منفذة فعلياً** (S1–S10 من الخطة السابقة) والخطة التالية تركز على الفجوات المتبقية.

---

## 🔴 P0 — ثغرات أمنية (حرجة)

### I1: SHA256 verification في install.sh
- **الوصف**: سكريبت `install.sh` يستخدم `curl | bash` بدون التحقق من checksum — ثغرة supply chain
- **الحل**: تحميل `checksums.txt` من الـ release، التحقق من SHA256 قبل التنصيب
- **الملفات**: `deploy/install.sh`, `Makefile`
- **الجهد**: ساعات

### I2: Event bus buffer overflow
- **الوصف**: الـ buffer محدود بـ 1000 حدث non-blocking drop — تحت هجوم مكثف تضيع أحداث
- **الحل**: رفع الحد إلى 10000 + تسجيل counter + log warning عند الإسقاط
- **الملفات**: `internal/pipeline/bus.go`
- **الجهد**: ساعة

### I3: لا IP Whitelist
- **الوصف**: لا آلية لحماية IPs مهمة (DevOps, monitoring) من الحجب العرضي
- **الحل**: إضافة `firewall.whitelist` في `config.yaml` — قبل أي حجب، نتحقق من الـ whitelist
- **الملفات**: `internal/config/config.go`, `internal/engine/decision.go`, `config.yaml`, `deploy/install.sh`
- **الجهد**: يوم

---

## 🟡 P1 — تحسينات عالية

### I4: دعم IPv6
- **الوصف**: nftables set type `ipv4_addr` فقط — المهاجم عبر IPv6 لا يُحجب
- **الحل**: إنشاء set ثنائي `{ ipv4_addr, ipv6_addr }` مع `flags interval`
- **الملفات**: `internal/firewall/nftables.go`, `internal/config/config.go`
- **الجهد**: أيام

### I5: توحيد اسم الـ binary
- **الوصف**: Makefile يبني `vps-guard` والـ README يشير لـ `vpsGuard`
- **الحل**: توحيد الكل على `vpsGuard` (تم جزئياً — restructure `cmd/`)
- **الملفات**: `Makefile`, `.github/workflows/*.yml`
- **الجهد**: ساعة

### I6: تفعيل config_checksum افتراضياً
- **الوصف**: السمة موجودة لكن `config_checksum: ""` فارغ — غير مفعلة
- **الحل**: عند أول تشغيل، الـ agent يحسب SHA256 لـ config.yaml ويخزنه
- **الملفات**: `internal/selfprotect/watchdog.go`, `internal/config/config.go`
- **الجهد**: ساعات

---

## 🔵 P2 — تحسينات متوسطة

### I7: OTX score بدالة مستمرة
- **الوصف**: نقاط OTX تقفز فجأة (0→15→35→55→75→90) — سلوك غير متوقع عند الحدود
- **الحل**: استخدام دالة مستمرة مثل `min(90, pulses * 3.6)` أو sigmoid mapping
- **الملفات**: `internal/threat/alienvault.go`
- **الجهد**: ساعات

### I8: استبدال exec.Command لـ nftables
- **الوصف**: fork عملية لكل IP → overhead. البديل: native netlink library
- **الحل**: استخدام `github.com/google/nftables` (pure Go netlink)
- **الملفات**: `internal/firewall/nftables.go`, `go.mod`
- **الجهد**: أسابيع

---

## 🟣 P3 — طويلة المدى

### I9: تشفير API keys في vault
- **الوصف**: مفاتيح AbuseIPDB وAlienVault وTelegram وSMTP مخزنة plain text
- **الحل**: إضافة encrypted vault (age أو AES-GCM مع master key في env var)
- **الملفات**: `internal/config/config.go`, ملف جديد `internal/config/vault.go`
- **الجهد**: أسابيع

---

## خريطة الطريق

| المرحلة | البنود | الجهد التقديري |
|---------|--------|---------------|
| v0.3.0-alpha | I1 (SHA256) | ساعات |
| v0.3.0-beta  | I2 (buffer) + I3 (whitelist) | يوم |
| v0.3.0       | I4 (IPv6) + I5 (توحيد الاسم) | أيام |
| v0.4.0       | I6 (checksum) + I7 (OTX) | أيام |
| v0.5.0       | I8 (nftables lib) | أسابيع |
| v0.6.0       | I9 (vault) | أسابيع |

---

## ✅ تم إنجازه سابقاً (S1–S10)
_لا حاجة لإعادته — كلها منفذة وموثقة في الكود_

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

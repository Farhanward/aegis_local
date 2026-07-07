# Changelog — aegis-local

## 1.0.0 — 2026-07-05 (الترقية المؤسسية)

- **خدمة HTTP للبوابة**: `aegis/service.py` — `POST /api/gate` (قرارات فقط؛ التنفيذ CLI-only عمداً)، `/api/health`، `/api/version`، `/api/metrics`، `/api/ledger/verify`، تسجيل اختياري في السجل الموقع عبر `"record": true`.
- **Config مركزي عبر البيئة**: `aegis/config.py` (`AEGIS_*`).
- **Observability**: `aegis/observability.py` — سجلات JSON بتدوير + عدادات قرارات وp50/p95/p99.
- **مصادقة وحدود**: `X-API-Key` بمقارنة constant-time، حد حجم الطلب (413).
- **تغليف**: entry point `aegis`، أوامر `serve` و`version`.
- **توثيق**: `docs/OPERATIONS.md` + هذا الملف.
- **اختبارات enterprise**: 14 اختباراً جديداً (config/metrics/auth/gate عبر HTTP حقيقي).

## 0.1.0 — 2026-07-04

- بوابة الفعل الأولى: policy allowlist دقيقة + رفض رموز shell + تكامل المناعة + ledger موقع Ed25519 + benchmark 15,919 intent (F1=92.07%).

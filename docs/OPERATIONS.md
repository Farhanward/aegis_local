# دليل تشغيل AEGIS (Operations Runbook)

## 1) قرار أمني جوهري

خدمة HTTP تصدر **قرارات فقط** (`POST /api/gate`). التنفيذ الفعلي (`aegis run`) متاح عبر CLI فقط —
حتى لا يتحول AEGIS إلى remote shell إذا اختُرق عميل شبكي.

## 2) التهيئة عبر متغيرات البيئة

| المتغير | الافتراضي | الوظيفة |
|---|---|---|
| `AEGIS_HOME` | جذر المشروع | مجلد الحالة |
| `AEGIS_POLICY` | `<home>\config\aegis_policy.json` | سياسة السماح/المنع |
| `AEGIS_LEDGER` | `<home>\ledger\aegis-ledger.jsonl` | السجل الموقع Ed25519 |
| `AEGIS_API_KEY` | (فارغ = بلا مصادقة) | مفتاح `X-API-Key` لكل `/api/*` عدا health |
| `AEGIS_HOST` / `AEGIS_PORT` | `127.0.0.1` / `8788` | عنوان الخدمة |
| `AEGIS_MAX_BODY_BYTES` | `262144` | حد حجم الطلب (413) |
| `AEGIS_LOG_DIR` / `AEGIS_LOG_LEVEL` | `<home>\logs` / `INFO` | سجلات JSON |

## 3) تشغيل الخدمة

```powershell
$env:AEGIS_API_KEY = "مفتاح-قوي"
python -m aegis.cli serve
```

## 4) نقاط الفحص

- `GET /api/health` — مفتوح دائماً: `{ok, service, version, uptime_s, auth_required}`.
- `GET /api/version` · `GET /api/metrics` (p50/p95/p99 + عدادات القرارات) · `GET /api/ledger/verify`.
- `POST /api/gate` — جسم الطلب = ToolIntent JSON؛ أضف `"record": true` لتسجيل القرار في السجل الموقع.

مثال:

```powershell
curl -X POST http://127.0.0.1:8788/api/gate -H "X-API-Key: مفتاح-قوي" -H "Content-Type: application/json" -d '{"tool":"shell","command":"git status","cwd":"C:/Projects/aegis_local","record":true}'
```

## 5) السجلات والمقاييس

- `logs\aegis.service.jsonl`: JSON سطري لكل قرار `{action, tool, ms}` بتدوير 5MB×3.
- `/api/metrics`: `decision_allow/review/block/quarantine` + زمن p50/p95/p99.

## 6) النسخ الاحتياطي

- `ledger\aegis-ledger.jsonl` + `keys\aegis_ed25519_private.pem` (المفتاح الخاص = القدرة على التوقيع؛ خزّنه منفصلاً ومشفراً).
- `config\aegis_policy.json` (السياسة المعتمدة).

## 7) الحوادث الشائعة

| العرض | السبب | العلاج |
|---|---|---|
| كل القرارات REVIEW | الأمر خارج allowlist | حدّث `allowed_commands` في السياسة بوعي |
| `verify-ledger` يفشل | عبث أو مفتاح عام غير مطابق | جمّد السجل، تحقق من المفاتيح في `keys\` |
| 401 دائم | مفتاح API غير مطابق | طابق `X-API-Key` مع `AEGIS_API_KEY` |
| قرارات بطيئة | تحميل نموذج المناعة لكل نص طويل | تأكد من وجود `almunaa_lexical_guard.json` محلياً (يُحمَّل مرة ويُخزن) |

## 8) الترقية

1. أوقف الخدمة → حدّث الكود.
2. `python -m unittest discover -s tests -v` (الكل يجب أن ينجح).
3. `python -m aegis.cli verify-ledger` ثم أعد التشغيل وتحقق من `/api/health`.

# AEGIS Local — الند المحلي

تنفيذ أول لفكرة **AEGIS**: وكيل محلي مُحاسَب ومُشفّر. الهدف ليس تشغيل أوامر عمياء، بل تمرير كل فعل عبر بوابة قرار ثم تسجيله في دفتر Ed25519 قابل للتحقق.

## ما يفعله

- يقرأ `ToolIntent` بصيغة JSON.
- يمرره على بوابة أمان محلية.
- يتكامل اختيارياً مع `C:\Projects\almunaa` إذا كان موجوداً.
- ينفّذ فقط الأوامر المسموحة في `config\aegis_policy.json`.
- يستخدم `subprocess` بدون `shell=True`.
- يسجل القرار في ledger متصل بسلسلة hash.
- يوقّع كل record بتوقيع Ed25519.
- يتحقق لاحقاً من السلسلة والتوقيع ويرصد العبث.

## تشغيل سريع

```powershell
cd C:\Projects\aegis_local
python -m aegis.cli init
python -m aegis.cli run --input examples\safe_tool_intent.json
python -m aegis.cli run --input examples\dangerous_tool_intent.json
python -m aegis.cli verify-ledger
python -m unittest discover -s tests -v
```

## اختبار واسع

تم تحويل بيانات الإنترنت `neuralchemy/Prompt-injection-dataset` إلى tool intents خاصة بـ AEGIS:

```powershell
python -m aegis.cli make-benchmark --source C:\Projects\almunaa\data\benchmarks\neuralchemy_prompt_injection_full.events.jsonl --out data\benchmarks\aegis_neuralchemy_tool_intents.jsonl
python -m aegis.cli batch --input data\benchmarks\aegis_neuralchemy_tool_intents.jsonl --out reports\aegis_neuralchemy_benchmark.md --format md
python -m aegis.cli stress --input data\benchmarks\aegis_neuralchemy_tool_intents.jsonl --repeat 3 --out reports\aegis_neuralchemy_stress.md --format md
```

آخر نتائج:

- Benchmark: 15,919 سجل، F1 = 92.07%، precision = 94.68%، recall = 89.59%، specificity = 91.69%.
- Stress: 47,757 قرار بوابة، 0 أخطاء، p99 = 13.81ms، peak memory = 12.70MB.
- Ledger: تحقق `ledger verified`.

## الملفات

- `aegis\crypto.py`: مفاتيح وتوقيع Ed25519.
- `aegis\ledger.py`: hash-chain ledger والتحقق.
- `aegis\gate.py`: بوابة قرار الأدوات وتكامل المناعة.
- `aegis\policy.py`: سياسة السماح والمنع.
- `aegis\runner.py`: تنفيذ مقيد بعد السماح فقط.
- `aegis\batch.py`: قياس جودة وضغط.
- `aegis\datasets.py`: تحويل بيانات الإنترنت إلى tool intents.
- `aegis\cli.py`: واجهة أوامر.

## تحسينات إنتاجية

- سياسة السماح تطابق الحجج بدقة افتراضياً؛ لا يكفي أن يبدأ الأمر ببادئة مسموحة.
- `docker ps` وحده يقبل لاحقات قراءة محددة مثل `--format`, `--filter`, `--all`, `--quiet`, `--no-trunc`, و`--size`.
- رموز تحكم shell مثل `;`, `&&`, `||`, pipes, redirects, backticks, و`$(` تُرفض قبل التنفيذ.
- أنماط المنع التدميرية تُقيّم قبل رموز shell حتى يبقى الأمر الخطير `BLOCK` لا `REVIEW`.
- آخر اختبار ذاتي بعد التحسين: 7/7 ناجحة.

## الحالة

منتج CLI أولي مكتمل للفكرة. المرحلة التالية لاحقاً: واجهة RTL، موافقات بشرية متعددة، وربط أعمق مع «الميزان» لتقييم مخرجات الأدوات الحساسة.

## التشغيل المؤسسي (Enterprise) — v1.0.0

- **خدمة HTTP للبوابة**: `python -m aegis.cli serve` → `POST /api/gate` (قرارات فقط، التنفيذ CLI-only عمداً).
- **نقاط فحص**: `/api/health` (مفتوح) · `/api/version` · `/api/metrics` (p50/p95/p99 + عدادات القرارات) · `/api/ledger/verify`.
- **تهيئة عبر البيئة**: متغيرات `AEGIS_*` — انظر `docs/OPERATIONS.md`.
- **مصادقة**: اضبط `AEGIS_API_KEY` فيتطلب كل `/api/*` (عدا health) ترويسة `X-API-Key`.
- **سجلات JSON منظمة**: `logs\aegis.service.jsonl` بتدوير تلقائي.
- **سجل التغييرات**: `CHANGELOG.md`.

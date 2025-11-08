# Review Status Update

- Verified JWT pipeline now accepts both RS256 (public key) and HS256 (shared secret) tokens, matching issued session tokens across REST and Socket.IO.
- Confirmed HTTP и Socket.IO используют одну и ту же переменную окружения для HS256-секрета.
- Верифицирована проверка `audience`/`issuer` для всех JWT-потоков и обязательное поле `tokenVersion` для отзывов.
- Confirmed user object normalization now populates `req.user.id`, restoring downstream authorization and rate limiting.
- Observed key bundle routes reject invalid `userId` values and run validators when persisting payloads.
- Key bundle выдаёт ключи только разрешённым контактам (allowlist/членство в чате) и делает пометку атомарно.
- Registration endpoint now guards against duplicate usernames with explicit 400 responses.
- Зафиксирован отдельный риск-анализ (`docs/risk-analysis.md`) с потенциальными точками отказа и планом смягчения.

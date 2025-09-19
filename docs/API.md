# API Reference

## REST Endpoints

Полная спецификация доступна в файле [docs/api/openapi.yaml](api/openapi.yaml).

### POST /api/auth/register

- Тело: `{ username, email, password, publicKey }`
- Ответ: `201 { token, userId }`
- Ошибки: `400 missing_fields`, `400 user_exists`
  【F:server/src/routes/auth.js†L9-L32】

### POST /api/auth/login

- Тело: `{ email, password }`
- Ответ: `200 { token, userId }`
- Ошибки: `400 invalid_credentials`
  【F:server/src/routes/auth.js†L34-L44】

### POST /api/keybundle

- Требует JWT.
- Тело: `{ identityKey, signedPreKey, oneTimePreKeys: [{ keyId, publicKey }] }`
- Ответ: `204 No Content`
- Ошибки: `400 invalid_payload`, `500 server_error`
  【F:server/src/routes/keybundle.js†L5-L34】

### GET /api/keybundle/:userId

- Требует JWT.
- Ответ: `{ identityKey, signedPreKey, oneTimePreKey: { keyId, publicKey } }`
- Ошибки: `404 not_found`, `410 no_prekeys`
  【F:server/src/routes/keybundle.js†L36-L68】

### POST /api/messages

- Требует JWT.
- Тело: `{ chatId: ObjectIdString, encryptedPayload: Base64String }`
- Успех: `200 { ok: true, id }`
- Ошибки: `401 unauthenticated`, `403 forbidden`, `409 duplicate`, `413 ciphertext too large`, `422 invalid chatId/encryptedPayload`
  【F:server/src/routes/messages.js†L17-L68】

### GET /api/messages/:chatId

- Требует JWT.
- Ответ: `[{ id, chatId, senderId, encryptedPayload, createdAt }]`
- Ошибки: `401 unauthenticated`, `403 forbidden`, `422 invalid chatId`
  【F:server/src/routes/messages.js†L70-L95】

## Socket.IO

- Хендшейк: `Authorization: Bearer <JWT>` заголовок или `auth.token`.
- События:
  - `join { chatId }` → ack `{ ok: true }` при участии в чате, иначе `{ ok: false, error }`.
  - `message { id, chatId, senderId, encryptedPayload, createdAt }` — рассылается после записи в БД.
    【F:server/src/app.js†L78-L142】【F:server/src/routes/messages.js†L45-L68】

## Примеры

```json
POST /api/messages
{
  "chatId": "64f1c8e1b4c03f4a2d8f8c11",
  "encryptedPayload": "QUJDRA=="
}
```

```json
GET /api/messages/:chatId
[
  {
    "id": "64f1c8e1b4c03f4a2d8f8c12",
    "chatId": "64f1c8e1b4c03f4a2d8f8c11",
    "senderId": "64f1c8e1b4c03f4a2d8f8c13",
    "encryptedPayload": "QUJDRA==",
    "createdAt": "2024-10-15T12:00:00.000Z"
  }
]
```

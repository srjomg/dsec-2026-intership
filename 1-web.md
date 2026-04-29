# Executive Summary
В ходе анализа сценариев API были обнаружены и классифицированы по критичности следующие уязвимости:

| Critical | High | Medium | Low | Informational |
| -------- | ---- | ------ | --- | ------------- |
| 0        | 1    | 4      | 7   | 1             |
Общая оценка защищенности: 

Краткие выводы: 

---
# Технические детали
## High
### **F-H-1. Обход верификации подписи JWT**
#### Классификации
- CWE: CWE-347 - Improper Verification of Cryptographic Signature`
- OWASP: A04:2025 - Cryptographic Failures
- Критичности: High
#### Описание
Для авторизации действий (контроля доступа) API использует JWT (JSON Web Token) - токен авторизации, который указывается в Cookie в значении `session`.
**Технические данные**:
- Токен представлен в формате: `<header>.<body>.<signature>`, где `<signature> = xYz123`.
- Используемый алгоритм: `HS256`.
- Передаваемые в теле токена поля: `uid`, `username`, `role`.

В приложении реализована некорректная проверка подписи JWT.
В данном случае подпись статична и равна строке `xYz123`, из чего можно сделать вывод, что проверка не производится.

Правильный вариант вычисления подписи (псевдокод):
```
data = to_b64Url(header) + "." + to_b64Url(body)
hashed = HS256(data)
signature = to_b64Url(hashed)
```
#### Риски
- **Impersonation Attack**: атака с использованием подмены личности через подмену параметров `uid` и `username`.
- **Privilege Escalation**: повышение привилегий через подмену параметра `role`.
#### Рекомендации по устранению
- При реализации JWT использовать стандарты RFC 7519, 7515, 7517.
- Опираться на лучшие практики безопасности JWT: RFC 8725
- Использовать готовые и проверенные временем реализации JWT, например для Node.js - jsonwebtoken
## Medium
### **F-M-1. Stored XSS в `/api/v1/profile`**
#### Классификации
- CWE: CWE-79 - Improper Neutralization of Input During Web Page Generation
- OWASP: A05:2025 - Injection
- Критичности: Medium
#### Описание
Неправильная обработка пользовательского ввода при обновлении отображаемого имени в профиле пользователя влечет за собой возможность эксплуатации Stored XSS.
**Технические данные**:
- Уязвимая конечная точка: `/api/v1/profile`
- HTTP-метод: `POST`
- Уязвимый параметр: `display_name` 

**Пример запроса**:
```http
POST /api/v1/profile HTTP/1.1
Host: portal.targetcorp.com
Cookie: session=<DELETED>
Content-Type: application/json
Origin: https://portal.targetcorp.com
 
{"display_name": "<PAYLOAD_HERE>", "bio": "BIO"}
```
#### PoC
Получение Cookie пользователя:
```http
POST /api/v1/profile HTTP/1.1
Host: portal.targetcorp.com
Cookie: session=<DELETED>
Content-Type: application/json
Origin: https://portal.targetcorp.com
 
{"display_name": "<img src='' onerror='console.log(document.cookie)'>", "bio": "BIO"}
```
#### Риски
- Компрометация данных пользователя
- Выполнение действий от имени другого пользователя
- Порча сайта (defacing)
#### Рекомендации по устранению
- Экранирование данных (например, использование HTML-сущностей)
- Валидация данных (например, регулярные выражение, такие как `[a-zA-Z]+` и т.д.)
- Фильтрация (удаление опасных символов, таких как `>`, `<` и т.д.)
- Использование CSP (Content Security Policy)
- Использование библиотек и фреймворков с готовыми решениями (например, React, Angular)
### **F-M-2. Отсутствие проверки прав при сбросе пароля в `/api/v1/account/reset-password`**
#### Классификации
- CWE: CWE-862 - Missing Authorization
- OWASP: A01:2025 - Broken Access Control
- Критичности: Medium
#### Описание
### **F-M-3. Избыточное раскрытие данных / IDOR в `/api/v1/profile/{id}`**
#### Классификации
- CWE: CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor; CWE-639 - Authorization Bypass Through User-Controlled Key
- OWASP: A01:2025 - Broken Access Control
- Критичности: Medium
### **F-M-4. CSRF при смене почты в `/api/v1/account/change-email`**
#### Классификации
- CWE: CWE-352 - Cross-Site Request Forgery
- OWASP: A01:2025 - Broken Access Control
- Критичности: Medium
## Low
### **F-L-1. Использование предсказуемых ID пользователей**
#### Классификации
- CWE: CWE-340 - Generation of Predictable Numbers or Identifiers
- OWASP: A04:2025 - Cryptographic Failures
- Критичности: Low
### **F-L-2. Отсутствие времени жизни JWT** 
#### Классификации
- CWE: CWE-613 - Insufficient Session Expiration
- OWASP: A07:2025 - Authentication Failures
- Критичности: Low
### **F-L-3. Сброс пароля без повторения старого пароля в `/api/v1/account/reset-password`**
#### Классификации
- CWE: CWE-620 - Unverified Password Change
- OWASP: A07:2025 - Authentication Failures
- Критичности: Low
### **F-L-4. Отсутствие атрибутов безопасности Cookie**
### **F-L-5. Неправильная настройка политики CORS**
### **F-L-6. Отсутствие настройки CSP**
### **F-L-7. Отсутствие заголовка для защиты соединения (HSTS)**
## Informational
### **F-I-1. Раскрытие типа серверного фреймворка в `/profile/{id}`**
#### Классификации
- CWE: CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor
- OWASP: A01:2025 - Broken Access Control
- Критичности: Informational
#### Описание
Приложение раскрывает тип фреймворка (`Express.js`), используемого на серверной стороне через заголовок ответа `X-Powered-By` при посещении ресурсов `/profile/{id}`:
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Powered-By: Express
 
<!DOCTYPE html>
...
```
#### Риски
#### Рекомендации по устранению
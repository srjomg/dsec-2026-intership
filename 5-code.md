# Содержание

# Введение
В процессе аудита предстояло рассмотреть следующие файлы:
- `src/`
	- `app.py`
- `src/templates/`
	- `discount.html`

Были обнаружены следующие уязвимости:

| Critical | High | Medium | Low |
| -------- | ---- | ------ | --- |
| 0        | 3    | 4      | 5   |

| Уязвимость                                          | Критичность |
| --------------------------------------------------- | ----------- |
| F-H-1. SSRF при создании продукта                   | High        |
| F-H-2. Использование слабого секрета JWT            | High        |
| F-M-3. Плохое хеширование паролей                   | Medium      |
| F-M-4. Обход пути при загрузке файла                | Medium      |
| F-H-5. Обход пути при чтении файлов                 | High        |
| F-M-6. Изменение пароля без подтверждения текущего  | Medium      |
| F-L-7. Недостаточные требования к паролям           | Low         |
| F-L-8. JWT не аннулируются при выходе               | Low         |
| F-L-9. Небезопасные атрибуты Cookie                 | Low         |
| F-L-10. Открытое перенаправление                    | Low         |
| F-L-11. Доступ к потенциальным техническим ресурсам | Low         |

# Технические детали
## F-H-1. SSRF при создании продукта (High)
### Классификация
- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP: A01:2025 Broken Access Control
### Описание
Некорректная фильтрация пользовательского ввода при создании продукта ведет к SSRF.
### Ограничения
Необходимо иметь роль администратора для выполнения действий.
### Риск
- Прямой доступ к облачным данным, например на хост `169.254.169.254`, который используется, например в AWS для получения временных учетных данных.
- Внутренняя разведка
- Доступ к потенциальным внутренним ресурсам
### Затронутая область
Конечная точка: `/api/admin/create_product` (POST)

Файлы: `app.py` (функция `create_product`)

Код:
```python
# [...]
block_schemes = ["file", "gopher", "expect", "php", "dict", "ftp", "glob", "data"]
block_host = [ "127.0.0.1", "localhost", "#[...]"]
# [...]
@app.route("/api/admin/create_product", methods=["POST"])
@admin_required
@csrf_protect
def create_product():
	# [...]
    if reviews:
        decode_reviews = unquote(reviews)
        parsed = urlparse(decode_reviews)

        scheme = parsed.scheme.lower()
        
        ###
        # Плохой способ получения имени хоста.
	    # Лучше: parsed.hostname.lower()
        ###
        host = parsed.netloc.lower() # <---
        
        if parsed.username or parsed.password:
            return jsonify(error="Basic authentication in URL is not allowed"), 400
		
		###
		# Запрещаются все потенциально опасные схемы, но остаются:
		# http, https
		###
        if scheme in block_schemes: # <---
            return jsonify(error="Input scheme is forbidden"), 400
        
        ###
        # Возможно обойти черный список хостов через указание порта.
		# Например: localhost:80
        ###
        if host in block_host: # <---
            return jsonify(error="Input hostname is forbidden"), 400
        
        try:
            target = urllib.request.urlopen(reviews)
            return jsonify({"message":"Product created successfully",
                    "description":description,
                    "price":price,
                    "reviews":target.read().decode('utf-8')}), 201
        except Exception as e:
            return jsonify({"error": str(e), "message": "#[...]"}), 400

	# [...]
```
### PoC
Сделать POST-запрос на ресурс `/api/admin/create_product` и передать в параметре `reviews`, например: `https://localhost:5000/metrics`, `http://169.254.169.254/latest/meta-data/` (Cloud).
### Исправление
- Использовать белый список схем, например `{"http", "https"}`
- Сравнивать хост через `parsed.hostname.lower()`, а не через `parsed.netloc.lower()`.
- Заблокировать все приватные и зарезервированные адреса
- Использовать пересобранный URL для запроса
- Ограничить таймауты и размер ответа
## F-H-2. Использование слабого секрета JWT (High)
### Классификация
- CWE-347: Improper Verification of Cryptographic Signature
- OWASP: A04:2025 Cryptographic Failures
### Описание
Приложение использует слабый секрет JWT, что, при компрометации JWT может привести к его раскрытию.
```python
JWT_SECRET = "funkymonkey"
```
По информации из открытых источников:
- Встречается на "**Have I Been Pwned?**" больше **23000** раз.
- Встречается в "**Kaspersky Password Checker**" больше **4600** раз.
### Риск
- Подделка токенов
### Исправление
Придерживаться, например, следующих требований для токена:
- Длина: 28-32 символа.
- Энтропия: каждый бит секрета должен быть непредсказуемым.
- Для генерации использовать встроенные в язык и проверенные инструменты.
## F-M-3. Плохое хеширование паролей (Medium) 
### Классификация
- CWE-916: Use of Password Hash With Insufficient Computational Effort
- OWASP: A04:2025 Cryptographic Failures
### Описание
Для хранения в БД хешей паролей используется слабое хеширование - SHA256 с одной итерацией. 
### Риск
- Облегчение перебора паролей злоумышленником при компрометации хешей паролей.
### Затронутая область
Файлы: `app.py` (функция `hash_password`)

Код:
```python
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()
```
### Исправление
- Использовать проверенные алгоритмы: bcrypt, scrypt, Argon2, PBKDF2.
## F-M-4. Обход пути при загрузке файла (Medium)
### Классификация
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- OWASP: A01:2025 Broken Access Control
### Описание
Из-за неправильной обработки пользовательского ввода можно обойти путь и перезаписать файл за пределами установленного каталога.
### Ограничения
Для выполнения действий необходимо иметь роль администратора.
### Риск
- Перезапись файлов с определенными расширениями: jpg, jpeg, png, gif, txt, pdf.
### Затронутая область
Конечная точка: `/api/admin/upload` (POST)

Файлы: `app.py` (функция `upload_file`)

Код:
```python
# [...]
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "txt", "pdf"}
UPLOAD_FOLDER = "uploads"
# [...]
@app.route("/api/admin/upload", methods=["POST"])
@admin_required
@csrf_protect
def upload_file():
	# [...]
    if not is_allowed_file(file.filename):
        return jsonify(error="file extension not allowed"), 400

    ###
    # Неправильная фильтрация перехода в родительский каталог (../)
    # Можно обойти с помощью вложенных переходов:
    # ....// или ..././, также ....\\ или ...\.\
    ###
    filename = file.filename.replace("../", "").replace("..\\", "") # <---

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    return jsonify({"message": "file has been successfully uploaded"}), 200
```
### PoC
Совершить POST-запрос на `/api/admin/upload` с именем файла `....//some.txt`, чтобы записать файл `some.txt` рядом с папкой `upload/`. 
### Исправление
- При создании файла не доверять пользовательскому вводу и генерировать свое название для файла
- Применять списки разрешенных символов для имени файла (отделять расширение и проверять)
## F-H-5. Обход пути при чтении файлов (Medium)
### Классификация
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- OWASP: A01:2025 Broken Access Control
### Описание
Из-за неправильной обработки пользовательского ввода можно обойти путь и прочитать содержимое файла за пределами установленного каталога.
### Ограничения
Для выполнения действий необходимо иметь роль администратора.
### Риск
- Просмотр локальных файлов.
### Затронутая область
Конечная точка: `/api/admin/view?file=XXX` (GET)

Файлы: `app.py` (функция `view_file`)

Код:
```python
@app.route("/api/admin/view", methods=["GET"])
@admin_required
def view_file():
	# [...]
    ###
    # Неправильная фильтрация перехода в родительский каталог (../)
    # Можно обойти с помощью вложенных переходов:
    # ....// или ..././, также ....\\ или ...\.\
    ###
    filename = filename.replace("../", "").replace("..\\", "") # <---
    filepath = os.path.join(UPLOAD_FOLDER, filename)
	# [...]	
```
### PoC
Совершить GET-запрос на `/api/admin/view?file=....//....//....//....//....//....//etc/passwd` для прочтения файла `/etc/passwd`.
### Исправление
- Применять списки разрешенных символов для имени файла (отделять расширение и проверять)
## F-M-6. Изменение пароля без подтверждения текущего (Medium)
### Классификация
- CWE-620: Unverified Password Change
- OWASP: A07:2025 Authentication Failures
### Описание
Изменение пароля не требует указание текущего пароля.
### Риск
- При компрометации JWT пользователь может изменить пароль, не зная его.
### Затронутая область
Конечная точка: `/api/settings/password` (POST)

Файлы: `app.py` (функция `change_password`)
### Исправление
- Добавить проверку текущего пароля.
## F-L-7. Недостаточные требования к паролям (Low)
### Классификация
- CWE-521: Weak Password Requirements
- OWASP: A07:2025 Authentication Failures
### Описание
Слабая парольная политика: минимальная длина пароля - 5 символов, иных требований нет.
### Риск
- Облегчение брутфорса пароля
### Затронутая область
Конечная точка: `/api/auth/register` (POST), `/api/settings/password` (POST).

Файлы: `app.py` (функция `register`, `change_password`)

Код:
```python
def change_password():
    # [...]
    if len(pw) < 4: # <---
        return jsonify(error="[...]"), 400
	# [...]
```

```python
def register():
    # [...]
    if not username or not email or len(password) < 4: # <---
        return jsonify(error="[...]"), 400
	# [...]
```
### Исправление
Ужесточить требования по паролям, например:
- Минимальная длина - не менее 12 символов.
- Обязательное использование букв верхнего и нижнего регистра, цифр и специальных символов.
- Запрет на использование имени пользователя, названия компании, словарных слов, простых последовательностей, дат рождения, телефонных номеров и другой личной информации.
## F-L-8. JWT не аннулируются при выходе (Low)
### Классификация
- CWE-613: Insufficient Session Expiration
- OWASP: A07:2025 Authentication Failures
### Описание
При выходе пользователя из аккаунта JWT удаляются только на стороне браузера. Аннулирования токена не происходит.  
### Риск
- При компрометации токена, даже если пользователь выйдет из аккаунта - у злоумышленника также будет доступ.
### Затронутая область
Конечная точка: `/api/auth/logout` (POST)

Файлы: `app.py` (функция `logout`)

Код:
```python
@app.route("/api/auth/logout", methods=["POST"])
@auth_required
@csrf_protect
def logout():
    resp = jsonify(ok=True)
    resp.delete_cookie("token") # <---
    resp.delete_cookie("_csrf")
    return resp
```
### Исправление
- Сделать список аннулируемых токенов, хранящихся там до момента истечения
## F-L-9. Небезопасные атрибуты Cookie (Low)

### Классификация
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute
- OWASP: A01:2025 Broken Access Control
### Описание
Указан небезопасный `SameSite` атрибут, а также не указан атрибут `secure`.
### Риск
- Перехват Cookie
- Компрометация УЗ
### Затронутая область
Файлы: `app.py` (функция `set_auth_cookies`)

Код:
```python
def set_auth_cookies(resp, username, role):
    token = issue_token(username, role)
    resp.set_cookie("token", token, httponly=True, samesite=None, max_age=JWT_TTL)
    
    ###
    # Указание атрибута SameSite = None при HttpOnly = False влечет за собой риск
    # перехвата данных:
    # отправление при кросс-доменных запросах, через HTTP
    ###
    resp.set_cookie("_csrf", secrets.token_hex(32), httponly=False, samesite=None, max_age=JWT_TTL) # <---
    return resp
```
### Исправление
- Установить `samesite="Strict"` или `"Lax"`.
- Установить `secure=True`
## F-L-10. Открытое перенаправление (Low)
### Классификация
- CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
- OWASP: A01:2025 Broken Access Control
### Описание
Присутствует неконтролируемая функция открытого перенаправления 
### Риск
- Фишинг.
- Использование в комбинации с SSRF (F-H-1) для обхода фильтров.
### Затронутая область
Конечная точка: `/go` (GET)

Файлы: `app.py` (класс `ServiceMiddleware`, функция `__call__`)

Код:
```python
class ServiceMiddleware:
	# [...]
    def __call__(self, environ, start_response):
		# [...]
        if path == "/go":
            qs = environ.get("QUERY_STRING", "")
            target = urllib.parse.parse_qs(qs).get("url", ["/"])[0]
            target = urllib.parse.unquote(target)
            start_response("302 Found", [
                ("Location", target),
                ("Content-Length", "0"),
            ])
            return [b""]

        return self.wsgi(environ, start_response)
```
### PoC
Перейти по URL `/go?url=https://malicious.hack`
### Исправление
- Валидация URL-адресов перенаправления
## F-L-11. Доступ к потенциальным техническим ресурсам (Low)
### Классификация
- CWE-284: Improper Access Control
- OWASP: A01:2025 Broken Access Control
### Описание
Приложение не производит проверку доступа при просмотре потенциально внутренних технических ресурсов
### Риск
- Потенциальное раскрытие внутренней технической информации в будущем при добавлении или изменении функционала.
### Затронутая область
Конечная точка: `/health` (GET), `/metrics` (GET)

Файлы: `app.py` (класс `ServiceMiddleware`, функция `__call__`)

Код:
```python
class ServiceMiddleware:
	# [...]
    def __call__(self, environ, start_response):
        # [...]
        if path == "/health":
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b'{"status":"ok"}']

        if path == "/metrics":
            body = f'{{"uptime":{int(time.time() - self.boot)},"requests":{self.request_count}}}'.encode()
           # [...]
```
### Исправление
- Ограничить использование данных конечных точек только для администраторов.
# Цепочки эксплуатации
1) Пользователь может перехватить Cookie (F-L-9) или, зная логин, попытаться перебрать пароль, учитывая наличие слабой парольной политики (F-L-7).
2) После успешного перехвата JWT или перебора пароля и следовательно получение JWT пользователь может попробовать подобрать секрет для токена, учитывая его слабость (F-H-2).
3) После успешного подбора секрета пользователь теперь может подделать JWT и выдать себе роль `admin`.
4) Пользователю доступна запись/чтение локальных файлов, а также SSRF.
5) Так как он может читать локальные файлы, он сможет прочитать файлы исходного кода и затем прочитать файл БД, в котором пароли хранятся в слабом виде (F-M-3), что означает полную компрометацию учетных данных.
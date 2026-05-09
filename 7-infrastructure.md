# Введение
Необходимо восстановить его закрытый ключ сертификата и сам сертификат, который подписан **MOYKA ROOT CA** имея дамп файлов.
# Инструкция
## 1. Настройка
Для работы необходимо установить `mimikatz` и `openssl`.
После установки открываем PowerShell от имени Администратора и переходим в директорию дампа с папками `ProgramData` и `Windows`.
## 2. Извлечение секрета DPAPI_SYSTEM из реестра
```bash
mimikatz "lsadump::secrets /system:Windows\System32\config\SYSTEM /security:Windows\System32\config\SECURITY" exit
```

Вывод:
```
[...]
Secret  : DPAPI_SYSTEM
	[...]
    full: a0e9a91ca5fd7a82473c11e002ab613bad8c906e39bf9ba8af68b32aba14b83eb5b093b551f5bb56
    m/u : a0e9a91ca5fd7a82473c11e002ab613bad8c906e / 39bf9ba8af68b32aba14b83eb5b093b551f5bb56
    [...]
[...]
```

Отсюда необходимо взять `machine key` (`m`): `a0e9a91ca5fd7a82473c11e002ab613bad8c906e`.
## 3. Получаем GUID активного мастер-ключа
Выполняем следующий скрипт:
```powershell
$bytes = [IO.File]::ReadAllBytes("Windows\System32\Microsoft\Protect\S-1-5-18\Preferred")
$guid = [System.Guid]::new([byte[]]$bytes[0..15])
Write-Host $guid
```
Данный скрипт читает предпочтительный мастер-ключ.

Получаем: `c6859e4a-bfd8-46bf-86e7-2574c4b59eb2`.
## 4. Расшифровываем файлы мастер-ключа
Выполняем:
```bash
.\mimikatz.exe "dpapi::masterkey /in:Windows\System32\Microsoft\Protect\S-1-5-18\c6859e4a-bfd8-46bf-86e7-2574c4b59eb2 /system:a0e9a91ca5fd7a82473c11e002ab613bad8c906e" exit
```

Получаем:
```
[...]
[masterkey] with DPAPI_SYSTEM: a0e9a91ca5fd7a82473c11e002ab613bad8c906e
  key : 43d0f1e158b63d8e5e992cb886a142bdce9f7c0404417f39699e7f53e73183f7bbf090a918bde8cb1c9821dac4094f5a2c2ad18e0642d4c0667a7f5c9b2d81a7
[...]
```

Отсюда берем ключ: `43d0f1e158b63d8e5e992cb886a142bdce9f7c0404417f39699e7f53e73183f7bbf090a918bde8cb1c9821dac4094f5a2c2ad18e0642d4c0667a7f5c9b2d81a7`.
## 5. Расшифровываем приватный RSA-ключ сертификата
```bash
.\mimikatz.exe "dpapi::masterkey /in:Windows\System32\Microsoft\Protect\S-1-5-18\c6859e4a-bfd8-46bf-86e7-2574c4b59eb2 /system:a0e9a91ca5fd7a82473c11e002ab613bad8c906e" "dpapi::capi /in:ProgramData\Microsoft\Crypto\RSA\MachineKeys\fc58e716dd94cece30c087d4db914620_e1d345bd-ebc1-4d50-8b78-3f3e787e0953" exit
```

Получаем:
```
[...]
        Exportable key : YES
        Private export : OK - 'dpapi_exchange_capi_0_{9D947440-8500-4E0D-81D9-EFBA81B82D97}.keyx.rsa.pvk'
[...]
```
Теперь в той же директории сохранен приватный RSA ключ в файле `dpapi_exchange_capi_0_{9D947440-8500-4E0D-81D9-EFBA81B82D97}.keyx.rsa.pvk`.
## 6. Загружаем оффлайн куст SOFTWARE в реестр
```bash
reg load HKLM\OFFLINE Windows\System32\config\SOFTWARE
```
## 7. Находим сертификаты в загруженном кусте
```bash
reg query "HKLM\OFFLINE\Microsoft\SystemCertificates" /s /f "Certificates"
```

Получаем ветку с "нашими" сертификатами:
```
[...]
HKEY_LOCAL_MACHINE\OFFLINE\Microsoft\SystemCertificates\MY\Certificates
[...]
```

Смотрим внутри него:
```bash
reg query "HKLM\OFFLINE\Microsoft\SystemCertificates\MY\Certificates"
```

Получаем:
```bash
HKEY_LOCAL_MACHINE\OFFLINE\Microsoft\SystemCertificates\MY\Certificates\DB74D352754B27D58F8DA91B772F223718922619
```
В нем хранится Blob с байтами сертификата.
## 8. Извлекаем сертификат
	Извлекаем DER байты из Blob:
```powershell
$blob = (Get-ItemProperty "HKLM:\OFFLINE\Microsoft\SystemCertificates\MY\Certificates\DB74D352754B27D58F8DA91B772F223718922619").Blob; $i=0; while($i -lt $blob.Length){ $propId=[BitConverter]::ToUInt32($blob,$i); $i+=4; $i+=4; $size=[BitConverter]::ToUInt32($blob,$i); $i+=4; if($propId -eq 32){ [IO.File]::WriteAllBytes("cert.cer",$blob[$i..($i+$size-1)]); Write-Host "Saved $size bytes"; break }; $i+=$size }
```
Получили `cert.cer`

Преобразуем его в PEM:
```bash
certutil -encode cert.cer cert.pem
```
## 9. Конвертируем приватный ключ в PEM
```bash
openssl rsa -inform PVK -in 'dpapi_exchange_capi_0_{9D947440-8500-4E0D-81D9-EFBA81B82D97}.keyx.rsa.pvk' -out key.pem
```
## 10. Проверка соответствия ключей сертификату
```
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl x509 -noout -modulus -in key.pem | openssl md5
```

Получаем:
```
MD5(stdin)= ecaa88f7fa0bf610a5a26cf545dcd3aa
MD5(stdin)= ecaa88f7fa0bf610a5a26cf545dcd3aa
```

MD5 совпадают, следовательно ключ и сертификат являются парой.

Также можем вывести данные сертификата 
```bash
openssl x509 -in cert.pem -noout -text
```
где видим:
```
[...]
Issuer: C=RU, ST=St. Petersburg, L=St. Petersburg, O=MOYKA, CN=MOYKA ROOT CA
[...]
Subject: C=RU, ST=St. Petersburg, L=St. Petersburg, O=MOYKA, CN=IVANOV-NB
[...]
```
Значит, всё получилось!
# Приложение
## Содержимое `cert.pem`
```
-----BEGIN CERTIFICATE-----
MIIFUTCCAzkCFCl/h76wv/zF2+BDk5d2yBs0G1K5MA0GCSqGSIb3DQEBCwUAMGcx
CzAJBgNVBAYTAlJVMRcwFQYDVQQIDA5TdC4gUGV0ZXJzYnVyZzEXMBUGA1UEBwwO
U3QuIFBldGVyc2J1cmcxDjAMBgNVBAoMBU1PWUtBMRYwFAYDVQQDDA1NT1lLQSBS
T09UIENBMB4XDTI2MDQwMTAyMDIwMFoXDTI3MDQwMTAyMDIwMFowYzELMAkGA1UE
BhMCUlUxFzAVBgNVBAgMDlN0LiBQZXRlcnNidXJnMRcwFQYDVQQHDA5TdC4gUGV0
ZXJzYnVyZzEOMAwGA1UECgwFTU9ZS0ExEjAQBgNVBAMMCUlWQU5PVi1OQjCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANYGhIjnROymnT9O534afYhk0gq5
8/RAR2f/X7WLE4BdARnCrCy1SNWwqbLfjkNyLM8cLUEjYKl11kjPeHlfO6CLNMVG
3M8M6P4emz6frYPXJnEDcJQ3BsuMPH0zhIBK9N9gqvwxtyRWNSkcw9GqTQqofLQ2
e3sxGxat2TM1+giI818mgaZ97mrxAyo1r9OFlZKOwRBMEPgQcPXuoBZYE0WxSwwP
KzN3cz3pgzfCGzUdFCIhNY6z9+F0X773g2ccIMRASCFQ9YtJC9mYu4MATPUyr6+s
EEdZ0qD53s7jmwfVTZYAiwdu7vMnb8J+RZ2nU7MVM4rXsf6wlt/UuKipbq4SW6ZD
UaoX8Owjge0a/bT4KK3eqGobQRq+TkD78SjncdVOksibcKR439UkbKT6pPGTDcC3
EslK7XHayAIUf+IzT/I18QFM5bOayT5TsUUAEUzV3sg8HrH+J0PZybi/FWskqnRe
QWJHxjwmpE0mxTnoOEQgrEj0Txg0NuOml2dqNgpp3S550efKXB6YA4UG2+jEVU7A
bGLFVliqFdOWlWgphiYsF3W6In4B6mlcnCuFz7DAtAOObhTQ8D1knnPig3p09izr
NLqbO/vtZZ1bU7o00CtfQC1k1ibzN7ipTJlaa479fnkAPoHr+I1E1OW/rprIwcPJ
2ILyGvkZAviz7L9/AgMBAAEwDQYJKoZIhvcNAQELBQADggIBADvL15FUWQfYnVqG
YocnafnOL/A9l8vorwgHVeOFMTh1nAfCQniKQrrlsOLM8vcvcE0QuBJVavoPt4Fi
/smvFQlAs23Y8EuRvSDqBuU9mDgJdejGmfVbFgcCll5PtCysja7sXSSSGFtfe9Iw
3JT5iMpuOV8NFP7JkhQHG1iVyxh9l3BSeeKKNlDLmMwmrPtExzoWsBwwK6hjrGPp
jRTCpTyTYL9+JynCj+rKI0jcu2TSH6rRx41nPGZwHB5j+OxU0uFlFcWHtOXoH998
PW3CimQDLey8CR+ujJr1l+QJNTWrAu6fg4fEeveMirR+8M5661ujGnPT/X7zIIVN
a42JW3zktanHrib1+xqVmmpUzdux665+H02YL7HxP5SyKZr/JD3u0oTRJN0j2Yqh
oDWWLZYLKkytGJdyxBV0Kh83+kHoFQ4Zkgej2XtWZ7shKpgIAQ6tUffI0OGXdJ0P
FmlHHCRW1ZEF8IA71lUVkVpIjW76OwD5Edts0GK1e8FuO1LLNNojV5liJnWyhxLd
86/0m0AF/8muyKxuQ/swQby1DvoSmlA/XodfnB72+Se90rUVxk/mEEXQ0DimvQ3p
qQY/cudMklmhqExGclWOjY8CuljPaNVxY5UXe8ztwgJ2vT/tjGTGIXUhLnSW9XkI
DtrDNyYck03iwRvwNPa9SQ1TgGfj
-----END CERTIFICATE-----
```
## Содержимое `key.pem`
```
-----BEGIN PRIVATE KEY-----
MIIJRAIBADANBgkqhkiG9w0BAQEFAASCCS4wggkqAgEAAoICAQDWBoSI50Tspp0/
Tud+Gn2IZNIKufP0QEdn/1+1ixOAXQEZwqwstUjVsKmy345DcizPHC1BI2CpddZI
z3h5XzugizTFRtzPDOj+Hps+n62D1yZxA3CUNwbLjDx9M4SASvTfYKr8MbckVjUp
HMPRqk0KqHy0Nnt7MRsWrdkzNfoIiPNfJoGmfe5q8QMqNa/ThZWSjsEQTBD4EHD1
7qAWWBNFsUsMDyszd3M96YM3whs1HRQiITWOs/fhdF++94NnHCDEQEghUPWLSQvZ
mLuDAEz1Mq+vrBBHWdKg+d7O45sH1U2WAIsHbu7zJ2/CfkWdp1OzFTOK17H+sJbf
1LioqW6uElumQ1GqF/DsI4HtGv20+Cit3qhqG0Eavk5A+/Eo53HVTpLIm3CkeN/V
JGyk+qTxkw3AtxLJSu1x2sgCFH/iM0/yNfEBTOWzmsk+U7FFABFM1d7IPB6x/idD
2cm4vxVrJKp0XkFiR8Y8JqRNJsU56DhEIKxI9E8YNDbjppdnajYKad0uedHnylwe
mAOFBtvoxFVOwGxixVZYqhXTlpVoKYYmLBd1uiJ+AeppXJwrhc+wwLQDjm4U0PA9
ZJ5z4oN6dPYs6zS6mzv77WWdW1O6NNArX0AtZNYm8ze4qUyZWmuO/X55AD6B6/iN
RNTlv66ayMHDydiC8hr5GQL4s+y/fwIDAQABAoICADea++Yhx/uAEky3cFeIBGNi
ZlvZEjO8W5D+fVxKZOetwjJyLI91DhZOztglUu3dBR1OIcfRrDR65BCIrrFB99jv
MeerUIUOwp37T7RGgitFw7wK+73WShKqPbD9qIg4cURz9hiNxhpPt4IV8h5QE7IY
MkYT/aL1ECelRVATzwFWq3xmIbsi7sWkFoFp72OSSlkIc8qLKMF6bA7JT5hei6tI
s8nPSxcVCsDkIW5kJPN4uZlgbWzE/zr5JEMWRXKNkUnLtbHKOfFVKhn/n4AanOP7
pj+LAbO394xRPv0bj1TKq1y0iWqF/Nj5vwSWD/o01f8qG/kPrzQPpzNCLjPLyXBA
sbsUbjIdYdYzscER4gs1psQIvMONbNoCNhVPuVfMeaVCPk0eLUyjsSXkD9dUkuXe
yhOxiPp7uCcQFVmJYf5qI+hMNBclHtZ7pwiRTPkcLcN4gqM373/v+UCL5xpOOAdu
zx98V2ia1oHMuNsjPiD/IP0lcdapV7V4xxNAyxfs9DCkZFgBWVETjXaiC6me83Rr
RbSFcunRzl9vjTyMEzEFxlOfUhXiL2xhtVbLE21h8l9E14x0n6rK24ra4eF1E5AH
cA3GRuwci4QcN8eSnanU3JhtPrrw/jHdcj+bx1QdIB7SeqltTHfmWbqOwYaLQUu4
cVl+IG2DgeAjM8IIGY3pAoIBAQDwl37kPawgYowxIzKRc6UWkK09eK5Wif0sJQAH
XIP5fAIX+IE9ewLlpC2n28w6LAep/iqS+sqZ70EbQCJZ1M/RZV7C8BWK3ruRvVU2
jzi0FgMYB0C2cvdabdJp38c3uzxaWD2wm5voSf4kFiT699GAtomHyPxRc2J3e8gP
jmh2T948k4FxpQgT3IKlvwegWiBYRHfNaj5Vh4PETGJnDTskLtYJHdRuXW0DqPH5
pcrjadUB8D+5X5YZpRpp0cWXcb0YdXg7vwTBhzf+JTugTEFuFdkc+gh1Kqr+oWV9
uqeeUeP0koeaIC4Edt/kjYoL+FDx4CVqqwYZxl0kHyLbN4ybAoIBAQDju3eM4qtT
hpAYf9L5eQarXPMuSt4ACYAfwkWDjZmcZ27fKoDp4inlqGSrCvg6kVLjmp9VSwIY
BJGKIq3v/T2mqpDNKY4d+y/874V1CMDJ/coD/ksl8pNcdLXnarbynx+MHPxGjfXZ
gdsPwttEEJSSt6e08X2h4BpYAOoggmwe6Y++naPdgFOS+lJT3rVSOUOISNU3yWV7
bVONmMmd1QxOKkMqsUOIs6mUsxfJxJ61QWFfXuf1aPQ4olQfXlWSmvJvR7hdLZjP
l9u9KB5WiDWTxJnT3rsrZtJd3DTb/bdkcWmvGHpWd/pnbfAQVjF1BM0g4dw0DwRq
hkKK6QTVNfztAoIBAQDDXxKQ/6/eIIidgmqXCOT/vP6hU3WnGqj3hxhN4gfduaDt
nEQ/C7xfhQH6NJfUiVqz5YznDDcn58zj9yGt9w3Hidz4ygOEYLjKcYhYJNe0Dcf3
ZDRdtGA/E71xcmIRVL9+0fdOih6B9EwnO8BN+J4tOo3WMRUMg3lrc54TW95ibRsX
7+SGx7AWiNOjCsyDn4xygS8UJPl3dPNAnZKvAmSLTmlKv+l4se9LsI7G3qYyJAfw
agslWoTGUHdxhQJCp/8ZdJLtWYHgMhD7FXslAaeEYMONL1Fc7AgtfByxi7h/7RoC
ylbJhuY3g9zueS2n6L66m/1mcHkkxxttsMcaYzKPAoIBAQDAABAdMgYsV6kpXqur
NYSP+b/1aZ2d/mSNYidlcH7wRKxPbvBdQBb+z2iAZLE//8IYrwZizOipA0EJa4+m
ZKYT3H5U2xI86MhewjqMn6KbKmOl1kHZbpkbPDMZNvmjuNDKOq3fdlSu2zKsKSbg
TfJVeI3mmivHzL+pLqw2WH972IMevJ2pZEYSBwZeO8g32Ju9TVqmvB/ZXiUxnn1t
mm/TfwI9/lHn8UGqYwxNSn5cZxEHbWa3m5M8JHA0Oj5/ai+37onb1VOewnO7GRXq
8s/pE7p1zLWVNA1soPnX+CMkhhIKU+LhACqYBTJ/M4xjEnc3n/Ud1wNsJGH559fx
QqFJAoIBAQDAQR4DGAbB8M1p6dLGEwvkyYC+w9RqgE/oVq8MTKMVhHdy2IBaTQED
AuIC9iDn91u0gV4cL/5TmSPBjRsUnJiBSdWIqitCfbWc2Cql74/7qhpKagOz6Ykq
DOGvcxUPrUPlhpSjzODXR5fo+pM75KMByfeoA9Rq6yz7rFxtWVLXjLIIRqfP4cPb
q/73QfEsTspeB3KU42oOilrgOAskbE31vjZSUzAqoSSAe4g20E8tEZRYqt53/RLh
avKVotzkAzhaf/OC+/7/NwgOr2NVCHegsxZa0SrZMhD4ILgKDWB0QjL+5ab2oHjB
cnfbssQPP7oCQDoIXDzYjN2L5PM4zmiI
-----END PRIVATE KEY-----
```
## Структура дампа
```
.
├── ProgramData
│   └── Microsoft
│       └── Crypto
│           ├── RSA
│           │   └── MachineKeys
│           │       └── fc58e716dd94cece30c087d4db914620_e1d345bd-ebc1-4d50-8b78-3f3e787e0953
│           └── SystemKeys
│               └── bdb27be877dde0b9ed3c6254c474af4f_e1d345bd-ebc1-4d50-8b78-3f3e787e0953
└── Windows
    ├── ServiceProfiles
    │   └── LocalService
    │       └── AppData
    │           └── Roaming
    │               └── Microsoft
    │                   └── Crypto
    │                       └── Keys
    │                           └── de7cf8a7901d2ad13e5c67c29e5d1662_e1d345bd-ebc1-4d50-8b78-3f3e787e0953
    └── System32
        ├── Microsoft
        │   └── Protect
        │       ├── Recovery
        │       └── S-1-5-18
        │           ├── 340bc26b-934e-4c87-b3fd-a876b3233d3e
        │           ├── 969458fd-aa12-4ae2-8ec3-a54e95f1ae1c
        │           ├── Preferred
        │           ├── User
        │           │   ├── 1c35e9ea-584a-4a5d-8bc7-bba62a0323b7
        │           │   ├── 38d7ec07-0147-4848-be7f-0d8f77ec2f8a
        │           │   ├── Diagnostic
        │           │   ├── Preferred
        │           │   └── e26aa568-e746-4187-8ab3-746f9439b197
        │           └── c6859e4a-bfd8-46bf-86e7-2574c4b59eb2
        └── config
            ├── SAM
            ├── SECURITY
            ├── SOFTWARE
            └── SYSTEM
```
# Signing dll's with fake Roblox certificate

* Download and unzip [secret-blox-sign](https://github.com/secret-blox/secret-blox-sign)
* Place unsigned.dll and hookloader.exe
* Run app.py
* Profit 🤑


# One time only
* Open regedit
* Open `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}` registry
* Change Dll value to "C:\\Windows\\System32\\ntdll.dll"
* Change FuncName to "DbgUiContinue"

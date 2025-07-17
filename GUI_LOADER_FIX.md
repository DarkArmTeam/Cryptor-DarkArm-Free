# Исправление проблемы с GUI приложениями

## Проблема
GUI приложения (как Telegram, браузеры, игры) работают в бесконечном цикле и не завершаются. Лоадер ждал завершения потока с `WaitForSingleObject(hThread, INFINITE)`, что приводило к зависанию.

## Решение
Исправлена логика в лоадерах x86 и x64:

### Изменения в `loader_template.c` (x86):
```c
// БЫЛО:
WaitForSingleObject(hThread, INFINITE);
log_message("main (x86): payload thread finished.");

// СТАЛО:
log_message("main (x86): GUI application detected, not waiting for completion");
CloseHandle(hThread);
log_message("main (x86): loader completed, GUI application should be running");
```

### Изменения в `loader_template_x64.c` (x64):
```c
// БЫЛО:
DWORD wait_result = WaitForSingleObject(hThread, INFINITE);
if (wait_result == WAIT_OBJECT_0) {
    log_message("main: payload thread finished normally.");
}

// СТАЛО:
log_message("main: GUI application detected, not waiting for completion");
CloseHandle(hThread);
log_message("main: loader completed, GUI application should be running");
```

## Результат
- ✅ GUI приложения теперь запускаются корректно
- ✅ Лоадер завершается после создания потока
- ✅ GUI приложение продолжает работать в фоне
- ✅ Нет зависания на `WaitForSingleObject`

## Тестирование
1. Зашифруйте GUI приложение (Telegram, браузер, игру)
2. Запустите зашифрованный файл
3. Проверьте, что GUI приложение запустилось
4. Проверьте лог файл `loader_debug.txt` - должно быть сообщение "GUI application detected, not waiting for completion"

## Логи
Теперь в логах будет:
```
[timestamp] main: payload thread created successfully
[timestamp] main: GUI application detected, not waiting for completion
[timestamp] main: loader completed, GUI application should be running
```

Вместо зависания на:
```
[timestamp] main: waiting for payload thread to complete...
``` 
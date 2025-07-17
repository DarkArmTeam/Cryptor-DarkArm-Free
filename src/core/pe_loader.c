#include "pe_loader.h"
#include <stdio.h>

// Logging macro
#define LOG_ERROR(ctx, fmt, ...) do { \
    snprintf(ctx->error_msg, sizeof(ctx->error_msg), fmt, ##__VA_ARGS__); \
    ctx->last_error = GetLastError(); \
    OutputDebugStringA(ctx->error_msg); \
} while(0)

BOOL load_pe_from_memory(LPVOID pe_buffer, SIZE_T buffer_size, PE_CONTEXT* ctx) {
    if (!pe_buffer || !ctx) return FALSE;
    ZeroMemory(ctx, sizeof(PE_CONTEXT));

    // Verify DOS header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pe_buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_ERROR(ctx, "Invalid DOS signature");
        return FALSE;
    }

    // Verify NT headers
    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((BYTE*)pe_buffer + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERROR(ctx, "Invalid NT signature");
        return FALSE;
    }

    // Verify machine type
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        LOG_ERROR(ctx, "Not a 64-bit PE file");
        return FALSE;
    }

    // Allocate memory for the image
    SIZE_T image_size = nt_headers->OptionalHeader.SizeOfImage;
    LPVOID base = VirtualAlloc(
        (LPVOID)nt_headers->OptionalHeader.ImageBase,
        image_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    if (!base) {
        // Try allocating at a different address
        base = VirtualAlloc(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!base) {
            LOG_ERROR(ctx, "Failed to allocate memory for PE image");
            return FALSE;
        }
    }

    ctx->base_address = base;
    ctx->image_size = image_size;

    // Map sections
    if (!map_pe_sections(pe_buffer, ctx)) {
        unload_pe(ctx);
        return FALSE;
    }

    // Process relocations if needed
    if ((ULONG_PTR)base != nt_headers->OptionalHeader.ImageBase) {
        if (!process_relocations(ctx)) {
            unload_pe(ctx);
            return FALSE;
        }
    }

    // Resolve imports
    if (!resolve_imports(ctx)) {
        unload_pe(ctx);
        return FALSE;
    }

    // Setup security cookie
    if (!setup_security_cookie(ctx)) {
        unload_pe(ctx);
        return FALSE;
    }

    // Calculate entry point
    ctx->entry_point = (LPVOID)((ULONG_PTR)base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    ctx->is_loaded = TRUE;

    return TRUE;
}

BOOL map_pe_sections(LPVOID pe_buffer, PE_CONTEXT* ctx) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pe_buffer;
    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((BYTE*)pe_buffer + dos_header->e_lfanew);
    
    // Copy headers
    memcpy(ctx->base_address, pe_buffer, nt_headers->OptionalHeader.SizeOfHeaders);

    // Map sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        LPVOID dest = (LPVOID)((ULONG_PTR)ctx->base_address + section->VirtualAddress);
        LPVOID src = (LPVOID)((ULONG_PTR)pe_buffer + section->PointerToRawData);
        
        if (section->SizeOfRawData > 0) {
            memcpy(dest, src, section->SizeOfRawData);
        } else {
            ZeroMemory(dest, section->Misc.VirtualSize);
        }

        DWORD protect = 0;
        DWORD characteristics = section->Characteristics;
        
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else {
            protect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }

        DWORD old_protect;
        if (!VirtualProtect(dest, section->Misc.VirtualSize, protect, &old_protect)) {
            LOG_ERROR(ctx, "Failed to set section protection");
            return FALSE;
        }
    }

    return TRUE;
}

BOOL process_relocations(PE_CONTEXT* ctx) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ctx->base_address;
    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((BYTE*)ctx->base_address + dos_header->e_lfanew);
    
    DWORD reloc_dir_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    DWORD reloc_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    
    if (!reloc_dir_size || !reloc_dir_rva) return TRUE;  // No relocations needed

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)ctx->base_address + reloc_dir_rva);
    LONG_PTR delta = (ULONG_PTR)ctx->base_address - nt_headers->OptionalHeader.ImageBase;
    
    while (reloc->VirtualAddress) {
        DWORD num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((ULONG_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < num_entries; i++) {
            if (entries[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                ULONG_PTR* address = (ULONG_PTR*)((ULONG_PTR)ctx->base_address + reloc->VirtualAddress + (entries[i] & 0xFFF));
                *address += delta;
            }
        }
        
        reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)reloc + reloc->SizeOfBlock);
    }
    
    return TRUE;
}

BOOL resolve_imports(PE_CONTEXT* ctx) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ctx->base_address;
    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((BYTE*)ctx->base_address + dos_header->e_lfanew);
    
    DWORD import_dir_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    DWORD import_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    if (!import_dir_size || !import_dir_rva) return TRUE;  // No imports needed
    
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ctx->base_address + import_dir_rva);
    
    while (import_desc->Name) {
        LPCSTR dll_name = (LPCSTR)((ULONG_PTR)ctx->base_address + import_desc->Name);
        HMODULE dll = LoadLibraryA(dll_name);
        
        if (!dll) {
            LOG_ERROR(ctx, "Failed to load DLL: %s", dll_name);
            return FALSE;
        }
        
        PIMAGE_THUNK_DATA64 first_thunk = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ctx->base_address + import_desc->FirstThunk);
        PIMAGE_THUNK_DATA64 orig_first_thunk = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ctx->base_address + import_desc->OriginalFirstThunk);
        
        while (first_thunk->u1.AddressOfData) {
            FARPROC function = NULL;
            
            if (orig_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                function = GetProcAddress(dll, (LPCSTR)(orig_first_thunk->u1.Ordinal & 0xFFFF));
            } else {
                PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)ctx->base_address + orig_first_thunk->u1.AddressOfData);
                function = GetProcAddress(dll, (LPCSTR)import_by_name->Name);
            }
            
            if (!function) {
                LOG_ERROR(ctx, "Failed to resolve import from %s", dll_name);
                return FALSE;
            }
            
            first_thunk->u1.Function = (ULONGLONG)function;
            first_thunk++;
            orig_first_thunk++;
        }
        
        import_desc++;
    }
    
    return TRUE;
}

BOOL setup_security_cookie(PE_CONTEXT* ctx) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ctx->base_address;
    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((BYTE*)ctx->base_address + dos_header->e_lfanew);
    
    DWORD load_config_dir_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    DWORD load_config_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    
    if (!load_config_dir_size || !load_config_dir_rva) return TRUE;  // No load config
    
    PIMAGE_LOAD_CONFIG_DIRECTORY64 load_config = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((ULONG_PTR)ctx->base_address + load_config_dir_rva);
    if (!load_config->SecurityCookie) return TRUE;  // No security cookie
    
    // Generate random cookie
    ULONGLONG cookie;
    if (!RtlGenRandom(&cookie, sizeof(cookie))) {
        cookie = (ULONGLONG)__rdtsc();  // Fallback to timestamp counter
    }
    cookie |= 0x2B992DDFA232;  // Add some constant value
    
    *(ULONGLONG*)((ULONG_PTR)ctx->base_address + load_config->SecurityCookie) = cookie;
    return TRUE;
}

// Thread creation code
#pragma pack(push, 8)
typedef struct _TRAMPOLINE_DATA {
    BYTE code[64];  // Trampoline code
    THREAD_PARAMS params;
} TRAMPOLINE_DATA;
#pragma pack(pop)

// Assembly trampoline (x64)
static const BYTE trampoline_code[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08,           // mov [rsp+8], rcx  ; Save rcx
    0x48, 0x89, 0x54, 0x24, 0x10,           // mov [rsp+16], rdx ; Save rdx
    0x4C, 0x89, 0x44, 0x24, 0x18,           // mov [rsp+24], r8  ; Save r8
    0x4C, 0x89, 0x4C, 0x24, 0x20,           // mov [rsp+32], r9  ; Save r9
    0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 40       ; Allocate shadow space
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,     // mov rcx, entry_point
    0x00, 0x00, 0x00, 0x00,
    0x48, 0xBA, 0x00, 0x00, 0x00, 0x00,     // mov rdx, base_address
    0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD1,                             // call rcx          ; Call entry point
    0x48, 0x83, 0xC4, 0x28,                 // add rsp, 40       ; Clean up shadow space
    0x48, 0x31, 0xC9,                       // xor rcx, rcx      ; Return 0
    0xC3                                    // ret
};

BOOL create_main_thread(PE_CONTEXT* ctx, HANDLE* out_thread) {
    if (!ctx || !ctx->is_loaded || !out_thread) return FALSE;

    // Allocate trampoline data
    TRAMPOLINE_DATA* trampoline = (TRAMPOLINE_DATA*)VirtualAlloc(
        NULL, 
        sizeof(TRAMPOLINE_DATA), 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    
    if (!trampoline) {
        LOG_ERROR(ctx, "Failed to allocate trampoline");
        return FALSE;
    }

    // Copy trampoline code
    memcpy(trampoline->code, trampoline_code, sizeof(trampoline_code));
    
    // Set up parameters
    trampoline->params.entry_point = ctx->entry_point;
    trampoline->params.base_address = ctx->base_address;
    trampoline->params.teb_address = NtCurrentTeb();
    
    // Patch entry point and base address into trampoline code
    *(ULONGLONG*)&trampoline->code[27] = (ULONGLONG)ctx->entry_point;
    *(ULONGLONG*)&trampoline->code[37] = (ULONGLONG)ctx->base_address;

    // Make trampoline executable
    DWORD old_protect;
    if (!VirtualProtect(trampoline, sizeof(TRAMPOLINE_DATA), PAGE_EXECUTE_READ, &old_protect)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        LOG_ERROR(ctx, "Failed to make trampoline executable");
        return FALSE;
    }

    // Create suspended thread
    *out_thread = CreateThread(
        NULL,                           // Default security
        0,                             // Default stack size
        (LPTHREAD_START_ROUTINE)trampoline,
        &trampoline->params,           // Thread parameter
        CREATE_SUSPENDED,              // Create suspended
        NULL                           // Thread ID not needed
    );

    if (!*out_thread) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        LOG_ERROR(ctx, "Failed to create thread");
        return FALSE;
    }

    return TRUE;
}

BOOL unload_pe(PE_CONTEXT* ctx) {
    if (!ctx || !ctx->base_address) return FALSE;
    
    VirtualFree(ctx->base_address, 0, MEM_RELEASE);
    ZeroMemory(ctx, sizeof(PE_CONTEXT));
    
    return TRUE;
} 
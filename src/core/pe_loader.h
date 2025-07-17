#pragma once

#include <windows.h>

typedef struct _PE_CONTEXT {
    LPVOID base_address;
    LPVOID entry_point;
    SIZE_T image_size;
    BOOL is_loaded;
    DWORD last_error;
    char error_msg[256];
} PE_CONTEXT;

// Main PE loading functions
BOOL load_pe_from_memory(LPVOID pe_buffer, SIZE_T buffer_size, PE_CONTEXT* ctx);
BOOL unload_pe(PE_CONTEXT* ctx);

// Internal functions
BOOL map_pe_sections(LPVOID pe_buffer, PE_CONTEXT* ctx);
BOOL process_relocations(PE_CONTEXT* ctx);
BOOL resolve_imports(PE_CONTEXT* ctx);
BOOL setup_security_cookie(PE_CONTEXT* ctx);

// Thread creation helpers
typedef struct _THREAD_PARAMS {
    LPVOID entry_point;
    LPVOID base_address;
    LPVOID teb_address;
    DWORD_PTR cookie;
} THREAD_PARAMS;

BOOL create_main_thread(PE_CONTEXT* ctx, HANDLE* out_thread); 
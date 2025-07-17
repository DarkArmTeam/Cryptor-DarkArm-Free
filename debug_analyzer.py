#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append('src')

from core.file_analyzer import FileAnalyzer

def debug_analyzer(file_path):
    """Отладка анализатора"""
    analyzer = FileAnalyzer()
    
    print(f"🔍 Отладка анализатора для файла: {file_path}")
    print("=" * 60)
    
    # Проверяем PE файл напрямую
    import pefile
    pe = pefile.PE(file_path)
    print(f"Прямая проверка PE:")
    print(f"  Machine: {hex(pe.FILE_HEADER.Machine)}")
    print(f"  is_exe(): {pe.is_exe()}")
    print(f"  is_dll(): {pe.is_dll()}")
    print(f"  Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
    
    print(f"\nАнализ через FileAnalyzer:")
    result = analyzer.analyze_file(file_path)
    
    if "pe_info" in result:
        pe_info = result["pe_info"]
        print(f"  Machine: {pe_info.get('machine', 'Unknown')}")
        print(f"  Machine name: {pe_info.get('machine_name', 'Unknown')}")
        print(f"  is_exe: {pe_info.get('is_exe', 'Unknown')}")
        print(f"  is_dll: {pe_info.get('is_dll', 'Unknown')}")
        print(f"  subsystem: {pe_info.get('subsystem', 'Unknown')}")
    else:
        print("  PE информация не найдена")
    
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python debug_analyzer.py <путь_к_файлу>")
        sys.exit(1)
    
    debug_analyzer(sys.argv[1]) 
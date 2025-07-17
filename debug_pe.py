#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pefile
import sys

def debug_pe(file_path):
    """Отладка PE файла"""
    print(f"🔍 Отладка PE файла: {file_path}")
    print("=" * 60)
    
    try:
        pe = pefile.PE(file_path)
        
        print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"Machine name: {pe.FILE_HEADER.Machine}")
        
        print(f"\nПроверка типов файлов:")
        print(f"is_dll(): {pe.is_dll()}")
        print(f"is_exe(): {pe.is_exe()}")
        print(f"is_driver(): {pe.is_driver()}")
        
        print(f"\nХарактеристики:")
        print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
        print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
        
        print(f"\nОпциональные заголовки:")
        print(f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"AddressOfEntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python debug_pe.py <путь_к_файлу>")
        sys.exit(1)
    
    debug_pe(sys.argv[1]) 
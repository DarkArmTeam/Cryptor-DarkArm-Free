#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import time
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.core.file_analyzer import FileAnalyzer

def debug_telegram_issue():
    """Диагностика проблемы с Telegram"""
    print("🔍 ДИАГНОСТИКА ПРОБЛЕМЫ С TELEGRAM")
    print("="*60)
    
    # Проверяем оригинальный файл
    original_file = "test_msgbox.exe"  # Используем доступный GUI файл
    encrypted_file = "test_msgbox_crypted.exe"
    
    if not os.path.exists(original_file):
        print(f"❌ Оригинальный файл не найден: {original_file}")
        return
    
    print(f"📁 Оригинальный файл: {original_file}")
    print(f"📏 Размер: {os.path.getsize(original_file):,} байт")
    
    # Анализируем оригинальный файл
    analyzer = FileAnalyzer()
    result = analyzer.analyze_file(original_file)
    
    if "error" in result:
        print(f"❌ Ошибка анализа: {result['error']}")
        return
    
    print(f"🏗️ Архитектура: {result.get('architecture', 'N/A')}")
    print(f"🎯 Подсистема: {result.get('pe_info', {}).get('subsystem', 'N/A')}")
    
    # Проверяем зашифрованный файл
    if os.path.exists(encrypted_file):
        print(f"\n📁 Зашифрованный файл: {encrypted_file}")
        print(f"📏 Размер: {os.path.getsize(encrypted_file):,} байт")
        
        # Проверяем, можно ли запустить оригинальный файл
        print(f"\n🧪 ТЕСТИРОВАНИЕ:")
        print("1. Попробуйте запустить оригинальный TelegramBuild.exe")
        print("2. Если оригинальный не запускается - проблема в самом файле")
        print("3. Если оригинальный запускается - проблема в лоадере")
        
        # Проверяем зависимости
        print(f"\n📦 ЗАВИСИМОСТИ:")
        deps = result.get('dependencies', [])
        for dep in deps[:5]:  # Показываем первые 5
            if 'error' not in dep:
                print(f"   • {dep.get('dll_name', 'N/A')}")
        
        # Проверяем секции
        print(f"\n📄 СЕКЦИИ:")
        sections = result.get('sections', [])
        for section in sections[:3]:  # Показываем первые 3
            if 'error' not in section:
                print(f"   • {section.get('name', 'N/A')} - {section.get('virtual_size', 0):,} байт")
        
        print(f"\n🎯 ВОЗМОЖНЫЕ ПРИЧИНЫ:")
        print("1. Telegram требует специфические зависимости")
        print("2. Проблема с правами доступа к памяти")
        print("3. Антивирус блокирует зашифрованный файл")
        print("4. Telegram требует определенные переменные окружения")
        print("5. Проблема с релокациями или импортами")
        
        print(f"\n🔧 РЕКОМЕНДАЦИИ:")
        print("1. Запустите оригинальный TelegramBuild.exe")
        print("2. Проверьте, работает ли он")
        print("3. Если работает - проблема в лоадере")
        print("4. Если не работает - проблема в самом файле")
        print("5. Попробуйте другой GUI файл (например, notepad.exe)")
        
    else:
        print(f"❌ Зашифрованный файл не найден: {encrypted_file}")

if __name__ == "__main__":
    debug_telegram_issue() 
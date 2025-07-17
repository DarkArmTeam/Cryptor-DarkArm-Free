#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptornor 2025 - Advanced PE Cryptor & Binder
Главный файл запуска
"""

import sys
import os
from pathlib import Path

# Добавляем путь к модулям
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    import customtkinter as ctk
    print("✅ customtkinter загружен")
    
    # Пробуем импортировать модули с обработкой ошибок
    try:
        from gui.main_window import MainWindow
        print("✅ main_window загружен")
    except ImportError as e:
        print(f"❌ Ошибка импорта main_window: {e}")
        sys.exit(1)
    
    try:
        from core.file_analyzer import FileAnalyzer
        print("✅ file_analyzer загружен")
    except ImportError as e:
        print(f"❌ Ошибка импорта file_analyzer: {e}")
        sys.exit(1)
    
    try:
        from core.cryptor_engine import CryptorEngine
        print("✅ cryptor_engine загружен")
    except ImportError as e:
        print(f"❌ Ошибка импорта cryptor_engine: {e}")
        sys.exit(1)
    
    try:
        from core.binder_engine import BinderEngine
        print("✅ binder_engine загружен")
    except ImportError as e:
        print(f"❌ Ошибка импорта binder_engine: {e}")
        sys.exit(1)
    
    try:
        from utils.logger import CryptorLogger
        print("✅ logger загружен")
    except ImportError as e:
        print(f"❌ Ошибка импорта logger: {e}")
        sys.exit(1)
    
    def main():
        """Главная функция"""
        try:
            print("🚀 Запуск Cryptornor 2025...")
            
            # Создание корневого окна
            root = ctk.CTk()
            
            # Создание компонентов
            file_analyzer = FileAnalyzer()
            cryptor_engine = CryptorEngine()
            binder_engine = BinderEngine()
            
            # Создание и запуск GUI
            app = MainWindow(root, file_analyzer, cryptor_engine, binder_engine)
            
            print("✅ GUI создан, запуск главного цикла...")
            
            # Запуск главного цикла
            root.mainloop()
            
        except Exception as e:
            print(f"❌ Критическая ошибка: {e}")
            import traceback
            traceback.print_exc()
            return 1
        
        return 0
    
    if __name__ == "__main__":
        exit_code = main()
        sys.exit(exit_code)
        
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    print("💡 Установите зависимости: pip install customtkinter pefile")
    sys.exit(1) 
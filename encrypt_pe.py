import sys
import os
import struct
import random
import hashlib
from datetime import datetime

def generate_key(size=32):
    """Генерация криптографически стойкого ключа"""
    return os.urandom(size)

def encrypt_data(data, key):
    """Улучшенное шифрование с использованием RC4 и key stretching"""
    # Key stretching через SHA-256
    stretched_key = hashlib.sha256(key).digest()
    
    # RC4 инициализация
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + stretched_key[i % len(stretched_key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    
    # Шифрование
    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        result.append(byte ^ k)
    
    return bytes(result)

def check_pe_file(data):
    """Проверка PE файла"""
    if len(data) < 0x40:
        return False, "Файл слишком маленький"
    
    # Проверка DOS сигнатуры
    dos_sig = struct.unpack('<H', data[0:2])[0]
    if dos_sig != 0x5A4D:  # 'MZ'
        return False, f"Неверная DOS сигнатура: 0x{dos_sig:04X}"
    
    # Проверка PE заголовка
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data):
        return False, "Неверное смещение PE"
    
    pe_sig = struct.unpack('<I', data[pe_offset:pe_offset+4])[0]
    if pe_sig != 0x4550:  # 'PE\0\0'
        return False, f"Неверная PE сигнатура: 0x{pe_sig:08X}"
    
    return True, "Валидный PE файл"

def generate_unique_name():
    """Генерация уникального имени для заголовочного файла"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    rand_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
    return f"payload_{timestamp}_{rand_suffix}"

def write_header(data, key, name):
    """Запись заголовочного файла"""
    with open(f"{name}.h", 'w') as f:
        f.write("// Автоматически сгенерированный зашифрованный payload\n")
        f.write(f"// Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Запись ключа
        f.write(f"unsigned char {name}_KEY[] = {{")
        f.write(','.join(f"0x{b:02X}" for b in key))
        f.write("};\n\n")
        
        # Запись данных
        f.write(f"unsigned char {name}_DATA[] = {{")
        for i, b in enumerate(data):
            if i % 12 == 0:
                f.write('\n    ')
            f.write(f"0x{b:02X},")
        f.write("\n};\n\n")
        
        # Запись размера
        f.write(f"unsigned int {name}_SIZE = {len(data)};\n")
        
        # Запись макросов для проверки
        f.write("\n// Макросы для проверки\n")
        f.write(f"#define {name}_KEY_SIZE {len(key)}\n")
        f.write(f"#define {name}_HASH \"{hashlib.sha256(data).hexdigest()}\"\n")

def main():
    if len(sys.argv) != 2:
        print("Использование: python encrypt_pe.py <input_file>")
        return
        
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Файл {input_file} не найден")
        return
        
    # Чтение файла
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Проверка PE файла
    valid, msg = check_pe_file(data)
    if not valid:
        print(f"Входной файл не является валидным PE: {msg}")
        return
    print("Входной файл является валидным PE")
    
    # Генерация ключа
    key = generate_key()
    print(f"Сгенерирован ключ размером {len(key)} байт")
    
    # Шифрование
    encrypted = encrypt_data(data, key)
    print(f"Зашифровано {len(encrypted)} байт")
    
    # Генерация имени
    unique_name = generate_unique_name()
    
    # Сохранение зашифрованного файла
    output_file = input_file.rsplit('.', 1)[0] + '_encrypted.exe'
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    print(f"Зашифрованный файл сохранен как: {output_file}")
    
    # Создание заголовочного файла
    write_header(encrypted, key, unique_name)
    print(f"Заголовочный файл сохранен как: {unique_name}.h")
    
    # Вывод информации для проверки
    print("\nИнформация для проверки:")
    print(f"Размер оригинального файла: {len(data)} байт")
    print(f"Размер зашифрованного файла: {len(encrypted)} байт")
    print(f"Хеш ключа (SHA-256): {hashlib.sha256(key).hexdigest()}")
    print(f"Хеш данных (SHA-256): {hashlib.sha256(encrypted).hexdigest()}")

if __name__ == '__main__':
    main() 
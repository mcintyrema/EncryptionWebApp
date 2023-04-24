using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionWebApp.Models
{
    public abstract class DESMethod{
        /// <summary>
            /// DES Encryption
            /// </summary>
            /// <param name="plain">Plain text for encryption.</param>
            /// <param name="encryptKey">keyfor encryption, length = 8</param>
            /// <returns>Return encrypted string. If fail, return null.</returns>
            public static string Encrypt(string encryptString, string encryptKey = "1234abcd")
            {
                try
                {
                    DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                    byte[] key = Encoding.ASCII.GetBytes(encryptKey);
                    byte[] iv = Encoding.ASCII.GetBytes(encryptKey);
                    byte[] dataByteArray = Encoding.UTF8.GetBytes(encryptString);

                    des.Key = key;
                    des.IV = iv;
                    string encrypt = "";
                    using (MemoryStream ms = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(dataByteArray, 0, dataByteArray.Length);
                        cs.FlushFinalBlock();
                        encrypt = Convert.ToBase64String(ms.ToArray());
                    }
                    return encrypt;
                }
                catch
                {
                    return null;
                }
            }

            /// <summary>
            /// DES Decryption
            /// </summary>
            /// <param name="cipher">Cipher text for decryption.</param>
            /// <param name="decryptKey">key for decrypt, length = 8</param>
            /// <returns>Return decripted string. If fail, return null.</returns>
            public static string Decrypt(string cipher, string decryptKey = "1234abcd")
            {
                try
                {
                    DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                    byte[] key = Encoding.ASCII.GetBytes(decryptKey);
                    byte[] iv = Encoding.ASCII.GetBytes(decryptKey);
                    des.Key = key;
                    des.IV = iv;

                    byte[] dataByteArray = Convert.FromBase64String(cipher);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(dataByteArray, 0, dataByteArray.Length);
                            cs.FlushFinalBlock();
                            return Encoding.UTF8.GetString(ms.ToArray());
                        }
                    }
                }
                catch
                {
                    return null;
                }
            }
    }

}
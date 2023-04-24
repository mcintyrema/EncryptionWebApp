using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;


namespace EncryptionWebApp.Models
{
    public class AESMethod{
        public AESMethod()
        {
            
        }

        private string Password ;

        public string GetPassword()
        {
            return this.Password;
        }

        public void SetPassword(string pass)
        {
            this.Password = pass;
        }

        public string Encrypt(string PlainText)
        {
            return Encrypt(PlainText, Password);
        }

        public string Decrypt(string CipherText)
        {
            return Decrypt(CipherText, Password);
        }

        #region EncryptDecrypt
        //http://www.gutgames.com/post/AES-Encryption-in-C.aspx
        //http://stackoverflow.com/questions/9237324/encrypting-decrypting-large-files-net

        /// <summary>
        ///	Encrypts a string
        ///	</summary>
        ///	<param name="PlainText">Text to be encrypted</param>
        ///	<param name="Password">Password to encrypt with</param>
        ///	<param name="Salt">Salt to encrypt with</param>
        ///	<param name="HashAlgorithm">Can be either SHA1 or MD5</param>
        ///	<param name="PasswordIterations">Number of iterations to do</param>
        ///	<param name="InitialVector">Needs to be 16 ASCII characters long</param>
        ///	<param name="KeySize">Can be 128, 192, or 256</param>
        ///	<returns>An encrypted string</returns>
        public static string Encrypt(string PlainText, string Password = "password",
	        string Salt = "Kosher", string HashAlgorithm = "SHA1",
	        int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY",
	        int KeySize = 256)
        {	
	        if (string.IsNullOrEmpty(PlainText))
	        return "";
	        byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
	        byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
	        byte[] PlainTextBytes = Encoding.UTF8.GetBytes(PlainText);
	        PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
	        byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
	        RijndaelManaged SymmetricKey = new RijndaelManaged();
	        SymmetricKey.Mode = CipherMode.CBC;
	        byte[] CipherTextBytes = null;
	        using (ICryptoTransform Encryptor = SymmetricKey.CreateEncryptor(KeyBytes, InitialVectorBytes))
	        {
	            using (MemoryStream MemStream = new MemoryStream())
	            {
	                using (CryptoStream CryptoStream = new CryptoStream(MemStream, Encryptor, CryptoStreamMode.Write))
	                {
	                    CryptoStream.Write(PlainTextBytes, 0, PlainTextBytes.Length);
	                    CryptoStream.FlushFinalBlock();
	                    CipherTextBytes = MemStream.ToArray();
	                    MemStream.Close();
	                    CryptoStream.Close();
	                }
	            }
	        }
	        SymmetricKey.Clear();
	        return Convert.ToBase64String(CipherTextBytes);
        }	
	
        ///	<summary>
        ///	Decrypts a string
        ///	</summary>
        ///	<param name="CipherText">Text to be decrypted</param>
        ///	<param name="Password">Password to decrypt with</param>
        ///	<param name="Salt">Salt to decrypt with</param>
        ///	<param name="HashAlgorithm">Can be either SHA1 or MD5</param>
        ///	<param name="PasswordIterations">Number of iterations to do</param>
        ///	<param name="InitialVector">Needs to be 16 ASCII characters long</param>
        ///	<param name="KeySize">Can be 128, 192, or 256</param>
        ///	<returns>A decrypted string</returns>
        public static string Decrypt(string CipherText, string Password = "password",
	        string Salt = "Kosher", string HashAlgorithm = "SHA1",
	        int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY",
	        int KeySize = 256)
        {	
	        if (string.IsNullOrEmpty(CipherText))
	        return "";
	        byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
	        byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
	        byte[] CipherTextBytes = Convert.FromBase64String(CipherText);
	        PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
	        byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
	        RijndaelManaged SymmetricKey = new RijndaelManaged();
	        SymmetricKey.Mode = CipherMode.CBC;
	        byte[] PlainTextBytes = new byte[CipherTextBytes.Length];
	        int ByteCount = 0;
	        using (ICryptoTransform Decryptor = SymmetricKey.CreateDecryptor(KeyBytes, InitialVectorBytes))
	        {
	            using (MemoryStream MemStream = new MemoryStream(CipherTextBytes))
	            {
	                using (CryptoStream CryptoStream = new CryptoStream(MemStream, Decryptor, CryptoStreamMode.Read))
	                {
	                    ByteCount = CryptoStream.Read(PlainTextBytes, 0, PlainTextBytes.Length);
	                    MemStream.Close();
	                    CryptoStream.Close();
	                }
	            }
	        }
	        SymmetricKey.Clear();
	        return Encoding.UTF8.GetString(PlainTextBytes, 0, ByteCount);
        }  	

        #endregion
    }

        // private static void DeriveKeyAndIV(string passphrase, byte[] salt, out byte[] key, out byte[] iv)
        // {
        //     // generate key and iv
        //     List<byte> concatenatedHashes = new List<byte>(48);

        //     byte[] password = Encoding.UTF8.GetBytes(passphrase);
        //     byte[] currentHash = new byte[0];
        //     MD5 md5 = MD5.Create();
        //     bool enoughBytesForKey = false;
        //     // See http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
        //     while (!enoughBytesForKey)
        //     {
        //         int preHashLength = currentHash.Length + password.Length + salt.Length;
        //         byte[] preHash = new byte[preHashLength];

        //         Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
        //         Buffer.BlockCopy(password, 0, preHash, currentHash.Length, password.Length);
        //         Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + password.Length, salt.Length);

        //         currentHash = md5.ComputeHash(preHash);
        //         concatenatedHashes.AddRange(currentHash);

        //         if (concatenatedHashes.Count >= 48)
        //             enoughBytesForKey = true;
        //     }

        //     key = new byte[32];
        //     iv = new byte[16];
        //     concatenatedHashes.CopyTo(0, key, 0, 32);
        //     concatenatedHashes.CopyTo(32, iv, 0, 16);

        //     md5.Clear();
        //     md5 = null;
        // }

        // private static byte[] EncryptStringToBytesAes(string plainText, byte[] key, byte[] iv)
        // {
        //     // Check arguments.
        //     if (plainText == null || plainText.Length <= 0)
        //         throw new ArgumentNullException("plainText");
        //     if (key == null || key.Length <= 0)
        //         throw new ArgumentNullException("key");
        //     if (iv == null || iv.Length <= 0)
        //         throw new ArgumentNullException("iv");

        //     // Declare the stream used to encrypt to an in memory
        //     // array of bytes.
        //     MemoryStream msEncrypt;

        //     // Declare the RijndaelManaged object
        //     // used to encrypt the data.
        //     RijndaelManaged aesAlg = null;

        //     try
        //     {
        //         // Create a RijndaelManaged object
        //         // with the specified key and IV.
        //         aesAlg = new RijndaelManaged { Mode = CipherMode.CBC, KeySize = 256, BlockSize = 128, Key = key, IV = iv };

        //         // Create an encryptor to perform the stream transform.
        //         ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        //         // Create the streams used for encryption.
        //         msEncrypt = new MemoryStream();
        //         using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        //         {
        //             using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
        //             {

        //                 //Write all data to the stream.
        //                 swEncrypt.Write(plainText);
        //                 swEncrypt.Flush();
        //                 swEncrypt.Close();
        //             }
        //         }
        //     }
        //     finally
        //     {
        //         // Clear the RijndaelManaged object.
        //         if (aesAlg != null)
        //             aesAlg.Clear();
        //     }

        //     // Return the encrypted bytes from the memory stream.
        //     return msEncrypt.ToArray();
        // }

        // private static string DecryptStringFromBytesAes(byte[] cipherText, byte[] key, byte[] iv)
        // {
        //     // Check arguments.
        //     if (cipherText == null || cipherText.Length <= 0)
        //         throw new ArgumentNullException("cipherText");
        //     if (key == null || key.Length <= 0)
        //         throw new ArgumentNullException("key");
        //     if (iv == null || iv.Length <= 0)
        //         throw new ArgumentNullException("iv");

        //     // Declare the RijndaelManaged object
        //     // used to decrypt the data.
        //     RijndaelManaged aesAlg = null;

        //     // Declare the string used to hold
        //     // the decrypted text.
        //     string plaintext;

        //     try
        //     {
        //         // Create a RijndaelManaged object
        //         // with the specified key and IV.
        //         aesAlg = new RijndaelManaged { Mode = CipherMode.CBC, KeySize = 256, BlockSize = 128, Key = key, IV = iv };

        //         // Create a decrytor to perform the stream transform.
        //         ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        //         // Create the streams used for decryption.
        //         using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        //         {
        //             using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        //             {
        //                 using (StreamReader srDecrypt = new StreamReader(csDecrypt))
        //                 {
        //                     // Read the decrypted bytes from the decrypting stream
        //                     // and place them in a string.
        //                     plaintext = srDecrypt.ReadToEnd();
        //                     srDecrypt.Close();
        //                 }
        //             }
        //         }
        //     }
        //     finally
        //     {
        //         // Clear the RijndaelManaged object.
        //         if (aesAlg != null)
        //             aesAlg.Clear();
        //     }

        //     return plaintext;
        // }

        // private static string Encrypt(string plainText, byte[] key, byte[] iv)
        // {
        //     // Instantiate a new Aes object to perform string symmetric encryption
        //     Aes encryptor = Aes.Create();

        //     encryptor.Mode = CipherMode.CBC;
        //     //encryptor.KeySize = 256;
        //     //encryptor.BlockSize = 128;
        //     //encryptor.Padding = PaddingMode.Zeros;

        //     // Set key and IV
        //     encryptor.Key = key;
        //     encryptor.IV = iv;

        //     // Instantiate a new MemoryStream object to contain the encrypted bytes
        //     MemoryStream memoryStream = new MemoryStream();

        //     // Instantiate a new encryptor from our Aes object
        //     ICryptoTransform aesEncryptor = encryptor.CreateEncryptor();

        //     // Instantiate a new CryptoStream object to process the data and write it to the 
        //     // memory stream
        //     CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);

        //     // Convert the plainText string into a byte array
        //     byte[] plainBytes = Encoding.ASCII.GetBytes(plainText);

        //     // Encrypt the input plaintext string
        //     cryptoStream.Write(plainBytes, 0, plainBytes.Length);

        //     // Complete the encryption process
        //     cryptoStream.FlushFinalBlock();

        //     // Convert the encrypted data from a MemoryStream to a byte array
        //     byte[] cipherBytes = memoryStream.ToArray();

        //     // Close both the MemoryStream and the CryptoStream
        //     memoryStream.Close();
        //     cryptoStream.Close();

        //     // Convert the encrypted byte array to a base64 encoded string
        //     string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);

        //     // Return the encrypted data as a string
        //     return cipherText;
        // }

        // private static string Decrypt(string cipherText, byte[] key, byte[] iv)
        // {
        //     // Instantiate a new Aes object to perform string symmetric encryption
        //     Aes encryptor = Aes.Create();

        //     encryptor.Mode = CipherMode.CBC;
        //     //encryptor.KeySize = 256;
        //     //encryptor.BlockSize = 128;
        //     //encryptor.Padding = PaddingMode.Zeros;

        //     // Set key and IV
        //     encryptor.Key = key;
        //     encryptor.IV = iv;

        //     // Instantiate a new MemoryStream object to contain the encrypted bytes
        //     MemoryStream memoryStream = new MemoryStream();

        //     // Instantiate a new encryptor from our Aes object
        //     ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();

        //     // Instantiate a new CryptoStream object to process the data and write it to the 
        //     // memory stream
        //     CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

        //     // Will contain decrypted plaintext
        //     string plainText = String.Empty;

        //     try
        //     {
        //         // Convert the ciphertext string into a byte array
        //         byte[] cipherBytes = Convert.FromBase64String(cipherText);

        //         // Decrypt the input ciphertext string
        //         cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);

        //         // Complete the decryption process
        //         cryptoStream.FlushFinalBlock();

        //         // Convert the decrypted data from a MemoryStream to a byte array
        //         byte[] plainBytes = memoryStream.ToArray();

        //         // Convert the encrypted byte array to a base64 encoded string
        //         plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
        //     }
        //     finally
        //     {
        //         // Close both the MemoryStream and the CryptoStream
        //         memoryStream.Close();
        //         cryptoStream.Close();
        //     }

        //     // Return the encrypted data as a string
        //     return plainText;
        // }
    
}
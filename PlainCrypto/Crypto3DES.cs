/* Dev By: Gilberto Hernandez 
 */
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PlainCrypto
{
    public sealed class Crypto3DES : ICrypto
    {
        private byte[] key;

        public Crypto3DES(byte[] key)
        {
            this.key = key;
        }

        public string Encrypt(string message)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(message);
                
                using(TripleDESCryptoServiceProvider provider = new TripleDESCryptoServiceProvider())
                {
                    provider.Key = this.key;
                    provider.Mode = CipherMode.CBC;
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        msEncrypt.Write(provider.IV, 0, 8);
                        using (ICryptoTransform encryptor = provider.CreateEncryptor())
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                csEncrypt.Write(data, 0, data.Length);
                                csEncrypt.FlushFinalBlock();
                                return Convert.ToBase64String(msEncrypt.ToArray());
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        public string Decrypt(string message)
        {
            try
            {
                byte[] data = Convert.FromBase64String(message);
                using (TripleDESCryptoServiceProvider provider = new TripleDESCryptoServiceProvider())
                {
                    provider.Key = this.key;

                    using (MemoryStream msDecrypt = new MemoryStream(data))
                    {
                        byte[] iv = new byte[8];
                        msDecrypt.Read(iv, 0, 8);
                        provider.IV = iv;

                        using (ICryptoTransform decryptor = provider.CreateDecryptor())
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {
                                    return srDecrypt.ReadToEnd();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}

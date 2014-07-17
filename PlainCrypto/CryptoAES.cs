/* Dev By: Gilberto Hernandez 
 */
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PlainCrypto
{
    public sealed class CryptoAES : ICrypto
    {
        private byte[] key;
        private byte[] iv;

        public CryptoAES(byte[] key, byte[] iv = null)
        {
            if (iv != null && iv.Length != 16)
            {
                throw new System.ArgumentException("Invalid IV length. IV Length must be 16");
            }
            else
            {
                this.iv = iv;
            }

            if (key.Length == 16 || key.Length == 24 || key.Length == 32)
            {
                this.key = key;
            }
            else
            {
                throw new System.ArgumentException("Invalid key length. Key length must be 16(AES128), 24(AES192) or 32(AES256)");
            }
        }

        public string Encrypt(string message)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(message);

                using(AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
                {
                    provider.Key = this.key;
                    provider.IV = (this.iv != null) ? this.iv : provider.IV;

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        if (this.iv == null)
                        {
                            msEncrypt.Write(provider.IV, 0, 16);
                        }
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
                using (AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
                {
                    provider.Key = this.key;

                    using (MemoryStream msDecrypt = new MemoryStream(data))
                    {
                        if (this.iv == null)
                        {
                            byte[] iv = new byte[16];
                            msDecrypt.Read(iv, 0, 16);
                            provider.IV = iv;
                        }
                        else
                        {
                            provider.IV = this.iv;
                        }

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

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PlainCrypto.Abstract
{
    public abstract class CryptoSymmetric : ICrypto
    {
        protected SymmetricAlgorithm cryptoServiceProvider;

        public abstract void SetIV(byte[] iv);

        /// <summary>
        ///     Encrypts the message supplied using the current settings.
        ///     The initialization vector(IV) will be written at the beginning of the encrypted message
        /// </summary>
        /// 
        /// <param name="message">
        ///     Message to be encrypted.
        /// </param>
        /// 
        /// <returns>
        ///     The encrypted message.
        /// </returns>
        public string Encrypt(string message)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(message);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    int ivLength = this.cryptoServiceProvider.LegalBlockSizes[0].MaxSize / 8;
                    msEncrypt.Write(this.cryptoServiceProvider.IV, 0, ivLength);

                    using (ICryptoTransform encryptor = this.cryptoServiceProvider.CreateEncryptor())
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
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        ///     Decrypts the message supplied using the current settings.
        ///     The initialization vector(IV) will be read from the beginning of the message
        /// </summary>
        /// 
        /// <param name="message">
        ///     Message to be decrypted.
        /// </param>
        /// 
        /// <returns>
        ///     The decrypted message.
        /// </returns>
        public string Decrypt(string message)
        {
            try
            {
                byte[] data = Convert.FromBase64String(message);

                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    int ivLength = this.cryptoServiceProvider.LegalBlockSizes[0].MaxSize / 8;
                    byte[] iv = new byte[ivLength];
                    msDecrypt.Read(iv, 0, ivLength);
                    this.cryptoServiceProvider.IV = iv;

                    using (ICryptoTransform decryptor = this.cryptoServiceProvider.CreateDecryptor())
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
            catch (Exception)
            {
                throw;
            }
        }
    }
}

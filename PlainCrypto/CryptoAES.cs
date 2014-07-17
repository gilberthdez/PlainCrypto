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
        private AesCryptoServiceProvider cryptoServiceProvider;

        /// <summary>
        ///     Initialize a new instance of the PlainCrypto.CryptoAES class.
        /// </summary>
        /// 
        /// <param name="key">
        ///     Expects a valid key for the AES specification. 
        ///     Valid key sizes are 128(16), 192(24) and 256(32) Bits(Bytes).
        /// </param>
        /// 
        /// <param name="iv">
        ///     Optional Parameter, if is not supplied it will be generated automatically. 
        ///     Expects a valid IV for the AES specification. 
        ///     The IV size must be 128(16) Bits(Bytes)
        /// </param>
        ///
        /// <exception name="Invalid key size">
        ///     System.ArgumentException
        ///         The supplied key is not valid for the AES specification.
        /// </exception>
        /// 
        /// <exception name="Invalid IV size.">
        ///     System.ArgumentException
        ///         The supplied IV is not valid for the AES specification.
        /// </exception>
        public CryptoAES(byte[] key, byte[] iv = null)
        {
            this.cryptoServiceProvider = new AesCryptoServiceProvider();

            if(this.cryptoServiceProvider.ValidKeySize(key.Length * 8))
            {
                this.cryptoServiceProvider.Key = key;
            }
            else
            {
                throw new System.ArgumentException("Invalid key size.", 
                    new System.Exception("The supplied key is not valid for the AES specification. Valid key sizes are 128(16), 192(24) and 256(32) Bits(Bytes)."));
            }

            if (iv != null)
            {
                if (this.cryptoServiceProvider.LegalBlockSizes[0].MaxSize == iv.Length * 8)
                {
                    this.cryptoServiceProvider.IV = iv;
                }
                else
                {
                    throw new System.ArgumentException("Invalid IV size.", 
                        new System.Exception("The supplied IV is not valid for the AES specification. The IV size must be 128(16) Bits(Bytes)"));
                }
            }
        }

        /// <summary>
        ///     Encrypts the message supplied using the current settings.
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

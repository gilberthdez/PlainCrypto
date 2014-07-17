/* Dev By: Gilberto Hernandez 
 */
using System;
using System.Security.Cryptography;
using PlainCrypto.Abstract;

namespace PlainCrypto
{
    public sealed class CryptoAES : CryptoSymmetric
    {
        /// <summary>
        ///     Initialize a new instance of the PlainCrypto.CryptoAES class.
        ///     The initialization vector(IV) will be generated automatically. 
        /// </summary>
        /// 
        /// <param name="key">
        ///     Expects a valid key for the AES specification. 
        ///     Valid key sizes are 128(16), 192(24) and 256(32)-Bits(Bytes).
        /// </param>
        ///
        /// <exception name="Invalid key size">
        ///     System.ArgumentException
        ///         The supplied key is not valid for the AES specification.
        /// </exception>
        public CryptoAES(byte[] key)
        {
            this.cryptoServiceProvider = new AesCryptoServiceProvider();

            if(!this.cryptoServiceProvider.ValidKeySize(key.Length * 8))
            {
                throw new System.ArgumentException("Invalid key size.", "key",
                    new System.Exception("The supplied key is not valid for the AES specification. Valid key sizes are 128(16), 192(24) and 256(32)-Bits(Bytes)."));
            }

            this.cryptoServiceProvider.Key = key;
        }

        /// <summary>
        ///     Sets the initialization vector(IV) for the current PlainCrypto.CryptoAES instance
        /// </summary>
        /// 
        /// <param name="iv">
        ///     Expects a valid IV for the AES specification.
        ///     The IV size must be 128(16)-Bits(Bytes)
        /// </param>
        /// 
        /// <exception name="Invalid IV size.">
        ///     System.ArgumentException
        ///         The supplied IV is not valid for the AES specification.
        /// </exception>
        public override void SetIV(byte[] iv)
        {
            if (this.cryptoServiceProvider.LegalBlockSizes[0].MaxSize == iv.Length * 8)
            {
                this.cryptoServiceProvider.IV = iv;
            }
            else
            {
                throw new System.ArgumentException("Invalid IV size.",
                    new System.Exception("The supplied IV is not valid for the AES specification. The IV size must be 128(16)-Bits(Bytes)"));
            }
        }
    }
}

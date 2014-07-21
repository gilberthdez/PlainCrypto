/* Dev By: Gilberto Hernandez 
 */
using System;
using System.Security.Cryptography;
using PlainCrypto.Abstract;

namespace PlainCrypto
{
    public sealed class CryptoDES : CryptoSymmetric
    {
        /// <summary>
        ///     Initialize a new instance of the PlainCrypto.CryptoDES class.
        /// </summary>
        /// 
        /// <param name="key">
        ///     Expects a valid key for the DES specification. 
        ///     The valid key size is 64(8)-Bits(Bytes).
        /// </param>
        /// 
        /// <exception name="Invalid key size">
        ///     System.ArgumentException
        ///         The supplied key is not valid for the DES specification.
        /// </exception>
        public CryptoDES(byte[] key)
        {
            this.cryptoServiceProvider = new DESCryptoServiceProvider();

            if (!this.cryptoServiceProvider.ValidKeySize(key.Length * 8))
            {
                throw new System.ArgumentException("Invalid key size.", "key",
                    new System.Exception("The supplied key is not valid for the DES specification. The valid key size is 64(8)-Bits(Bytes)."));
            }

            this.cryptoServiceProvider.Key = key;
        }

        /// <summary>
        ///     Sets the initialization vector(IV) for the current PlainCrypto.CryptoDES instance
        /// </summary>
        /// 
        /// <param name="iv">
        ///     Expects a valid IV for the DES specification.
        ///     The IV size must be 64(8)-Bits(Bytes)
        /// </param>
        /// 
        /// <exception name="Invalid IV size.">
        ///     System.ArgumentException
        ///         The supplied IV is not valid for the DES specification.
        /// </exception>
        public override void SetIV(byte[] iv)
        {
            if (!(this.cryptoServiceProvider.LegalBlockSizes[0].MaxSize == iv.Length * 8))
            {
                throw new System.ArgumentException("Invalid IV size.",
                    new System.Exception("The supplied IV is not valid for the DES specification. The IV size must be 64(8)-Bits(Bytes)"));
            }

            this.cryptoServiceProvider.IV = iv;
        }
    }
}

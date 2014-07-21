using PlainCrypto.Abstract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PlainCrypto
{
    public sealed class CryptoRC2 : CryptoSymmetric 
    {
        /// <summary>
        ///     Initialize a new instance of the PlainCrypto.CryptoRC2 class.
        /// </summary>
        /// 
        /// <param name="key">
        ///     Expects a valid key for the RC2 specification. 
        ///     The valid key size are 40(5) to 128(16)-Bits(Bytes) in increments of 8(1)-Bits(Byte).
        /// </param>
        /// 
        /// <exception name="Invalid key size">
        ///     System.ArgumentException
        ///         The supplied key is not valid for the RC2 specification.
        /// </exception>
        public CryptoRC2(byte[] key)
        {
            this.cryptoServiceProvider = new RC2CryptoServiceProvider();

            if (!this.cryptoServiceProvider.ValidKeySize(key.Length * 8))
            {
                throw new System.ArgumentException("Invalid key size.", "key",
                    new System.Exception("The supplied key is not valid for the RC2 specification. The valid key size are 40(5) to 128(16)-Bits(Bytes) in increments of 8(1)-Bits(Byte)."));
            }

            this.cryptoServiceProvider.Key = key;
        }

        /// <summary>
        ///     Sets the initialization vector(IV) for the current PlainCrypto.CryptoRC2 instance
        /// </summary>
        /// 
        /// <param name="iv">
        ///     Expects a valid IV for the RC2 specification.
        ///     The IV size must be 64(8)-Bits(Bytes)
        /// </param>
        /// 
        /// <exception name="Invalid IV size.">
        ///     System.ArgumentException
        ///         The supplied IV is not valid for the RC2 specification.
        /// </exception>
        public override void SetIV(byte[] iv)
        {
            if (!(this.cryptoServiceProvider.LegalBlockSizes[0].MaxSize == iv.Length * 8))
            {
                throw new System.ArgumentException("Invalid IV size.",
                    new System.Exception("The supplied IV is not valid for the RC2 specification. The IV size must be 64(8)-Bits(Bytes)"));
            }

            this.cryptoServiceProvider.IV = iv;
        }
    }
}

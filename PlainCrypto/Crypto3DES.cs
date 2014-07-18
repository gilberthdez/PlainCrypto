/* Dev By: Gilberto Hernandez 
 */
using System;
using System.Security.Cryptography;
using PlainCrypto.Abstract;

namespace PlainCrypto
{
    public sealed class Crypto3DES : CryptoSymmetric
    {
        /// <summary>
        ///     Initialize a new instance of the PlainCrypto.Crypto3DES class.
        /// </summary>
        /// 
        /// <param name="key1">
        ///     Expects a valid key for the TripleDES specification. 
        ///     The valid key size is 64(8)-Bits(Bytes).
        /// </param>
        /// 
        /// <param name="key2">
        ///     Expects a valid key for the TripleDES specification. 
        ///     The valid key size is 64(8)-Bits(Bytes).
        /// </param>
        /// 
        /// <param name="key3">
        ///     Optional parameter.
        ///     If not present, key3 = key1 operation will be asumed.
        ///     Expects a valid key for the TripleDES specification. 
        ///     The valid key size is 64(8)-Bits(Bytes).
        /// </param>
        ///
        /// <exception name="Invalid key size">
        ///     System.ArgumentException
        ///         The supplied key is not valid for the TripleDES specification.
        /// </exception>
        public Crypto3DES(byte[] key1, byte[] key2, byte[] key3 = null)
        {
            this.cryptoServiceProvider = new TripleDESCryptoServiceProvider();

            if (this.cryptoServiceProvider.LegalKeySizes[0].MaxSize / 3  != key1.Length * 8)
            {
                throw new System.ArgumentException("Invalid key size.","key1",
                    new System.Exception("The supplied key is not valid for the TripleDES specification. The valid key size is 64(8)-Bits(Bytes)."));
            }

            if (this.cryptoServiceProvider.LegalKeySizes[0].MaxSize / 3 != key2.Length * 8)
            {
                throw new System.ArgumentException("Invalid key size.", "key2",
                    new System.Exception("The supplied key is not valid for the TripleDES specification. The valid key size is 64(8)-Bits(Bytes)."));
            }

            if (key3 != null)
            {
                if (this.cryptoServiceProvider.LegalKeySizes[0].MaxSize / 3 != key3.Length * 8)
                {
                    throw new System.ArgumentException("Invalid key size.", "key3",
                        new System.Exception("The supplied key is not valid for the TripleDES specification. The valid key size is 64(8)-Bits(Bytes)."));
                }

                byte[] key = new byte[key1.Length + key2.Length + key3.Length];
                key1.CopyTo(key, 0);
                key2.CopyTo(key, key1.Length);
                key3.CopyTo(key, key1.Length + key2.Length);

                this.cryptoServiceProvider.Key = key;
            }
            else
            {
                byte[] key = new byte[key1.Length + key2.Length];
                key1.CopyTo(key, 0);
                key2.CopyTo(key, key1.Length);

                this.cryptoServiceProvider.Key = key;
            }
        }

        /// <summary>
        ///     Initialize a new instance of the PlainCrypto.Crypto3DES class.
        /// </summary>
        /// 
        /// <param name="keyBundle">
        ///     Expects a valid key bundle for the TripleDES specification
        ///     The valid key bundle sizes are 128(16) and 192(24)-Bits(Bytes).
        ///     The key bundle comprises the three DES keys into one single key.
        ///     For key3 = key1 operation, use a 128(16)-Bits(Bytes) key.
        ///     For independent keys operation, use a 192(24)-Bits(Bytes) key.
        /// </param>
        /// 
        /// <exception name="Invalid keyBundle size">
        ///     System.ArgumentException
        ///         The supplied keyBundle is not valid for the TripleDES specification.
        /// </exception>
        public Crypto3DES(byte[] keyBundle)
        {
            this.cryptoServiceProvider = new TripleDESCryptoServiceProvider();
            
            if (this.cryptoServiceProvider.ValidKeySize(keyBundle.Length * 8))
            {
                this.cryptoServiceProvider.Key = keyBundle;
            }
            else
            {
                throw new System.ArgumentException("Invalid keyBundle size.",
                        new System.Exception("The supplied keyBundle is not valid for the TripleDES specification. The valid key bundle sizes are 128(16) and 192(24)-Bits(Bytes)."));  
            }
        }

        /// <summary>
        ///     Sets the initialization vector(IV) for the current PlainCrypto.Crypto3DES instance
        /// </summary>
        /// 
        /// <param name="iv">
        ///     Expects a valid IV for the TripleDES specification.
        ///     The IV size must be 64(8)-Bits(Bytes)
        /// </param>
        /// 
        /// <exception name="Invalid IV size.">
        ///     System.ArgumentException
        ///         The supplied IV is not valid for the TripleDES specification.
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
                    new System.Exception("The supplied IV is not valid for the TripleDES specification. The IV size must be 64(8)-Bits(Bytes)"));
            }
        }
    }
}

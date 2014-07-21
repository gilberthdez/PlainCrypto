using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PlainCrypto.Abstract;
using PlainCrypto;

namespace PlainCryptoTest
{
    [TestClass]
    public class CryptoDES_Test
    {
        [TestMethod]
        public void CryptoDES_FixedIV_Test()
        {
            //Arrange
            byte[] key = { 158, 23, 64, 96, 57, 225, 36, 85 };
            byte[] iv = { 63, 208, 159, 46, 37, 77, 1, 59 };

            CryptoSymmetric crypto = new CryptoDES(key);
            crypto.SetIV(iv);
            string originalMessage = "I love cryptography and DES with a 64-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoDES_RandomIV_Test()
        {
            //Arrange
            byte[] key = { 158, 23, 64, 96, 57, 225, 36, 85 };

            CryptoSymmetric crypto = new CryptoDES(key);
            string originalMessage = "I love cryptography and DES with a 64-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }
    }
}

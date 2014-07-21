using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PlainCrypto;
using PlainCrypto.Abstract;

namespace PlainCryptoTest
{
    [TestClass]
    public class CryptoRC2_Test
    {
        [TestMethod]
        public void CryptoRC2_40Bit_FixedIV_Test()
        {
            //Arrange
            byte[] key = { 45, 6, 251, 89, 16 };
            byte[] iv = { 63, 208, 159, 46, 37, 77, 1, 59 };

            CryptoSymmetric crypto = new CryptoRC2(key);
            crypto.SetIV(iv);
            string originalMessage = "I love cryptography and RC2 with a 40-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoRC2_40Bit_RandomIV_Test()
        {
            //Arrange
            byte[] key = { 45, 6, 251, 89, 16 };

            CryptoSymmetric crypto = new CryptoRC2(key);
            string originalMessage = "I love cryptography and RC2 with a 40-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoRC2_64Bit_FixedIV_Test()
        {
            //Arrange
            byte[] key = { 158, 23, 64, 96, 57, 225, 36, 85 };
            byte[] iv = { 63, 208, 159, 46, 37, 77, 1, 59 };

            CryptoSymmetric crypto = new CryptoRC2(key);
            crypto.SetIV(iv);
            string originalMessage = "I love cryptography and RC2 with a 64-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoRC2_64Bit_RandomIV_Test()
        {
            //Arrange
            byte[] key = { 158, 23, 64, 96, 57, 225, 36, 85 };

            CryptoSymmetric crypto = new CryptoRC2(key);
            string originalMessage = "I love cryptography and RC2 with a 64-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoRC2_128Bit_FixedIV_Test()
        {
            //Arrange
            byte[] key = { 158, 23, 64, 96, 57, 225, 36, 85, 250, 23, 45, 94, 12, 36, 67, 170 };
            byte[] iv = { 63, 208, 159, 46, 37, 77, 1, 59 };

            CryptoSymmetric crypto = new CryptoRC2(key);
            crypto.SetIV(iv);
            string originalMessage = "I love cryptography and RC2 with a 128-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoRC2_128Bit_RandomIV_Test()
        {
            //Arrange
            byte[] key = { 158, 23, 64, 96, 57, 225, 36, 85, 250, 23, 45, 94, 12, 36, 67, 170 };

            CryptoSymmetric crypto = new CryptoRC2(key);
            string originalMessage = "I love cryptography and RC2 with a 128-bits key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }
    }
}

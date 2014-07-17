using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PlainCrypto;
using PlainCrypto.Abstract;

namespace PlainCryptoTest
{
    [TestClass]
    public class Crypto3DES_Test
    {
        [TestMethod]
        public void Crypto3DES_2Keys_FixedIV_Test()
        {
            //Arrange
            byte[] key1 = { 8, 207, 159, 63, 78, 21, 2, 16 };
            byte[] key2 = { 158, 23, 64, 96, 57, 225, 36, 85 };
            byte[] iv = { 63, 208, 159, 46, 37, 77, 1, 59 };

            CryptoSymmetric crypto = new Crypto3DES(key1, key2);
            crypto.SetIV(iv);
            string originalMessage = "I love cryptography and TripleDES with two 64-bits keys";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void Crypto3DES_2Keys_RandomIV_Test()
        {
            //Arrange
            byte[] key1 = { 8, 207, 159, 63, 78, 21, 2, 16 };
            byte[] key2 = { 158, 23, 64, 96, 57, 225, 36, 85 };

            CryptoSymmetric crypto = new Crypto3DES(key1, key2);
            string originalMessage = "I love cryptography and TripleDES with two 64-bits keys";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void Crypto3DES_3Keys_FixedIV_Test()
        {
            //Arrange
            byte[] key1 = { 8, 207, 159, 63, 78, 21, 2, 16 };
            byte[] key2 = { 158, 23, 64, 96, 57, 225, 36, 85 };
            byte[] key3 = { 49, 7, 210, 96, 13, 71, 62, 90 };
            byte[] iv = { 63, 208, 159, 46, 37, 77, 1, 59 };

            CryptoSymmetric crypto = new Crypto3DES(key1, key2, key3);
            crypto.SetIV(iv);
            string originalMessage = "I love cryptography and TripleDES with three 64-bits keys";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void Crypto3DES_3Keys_RandomIV_Test()
        {
            //Arrange
            byte[] key1 = { 8, 207, 159, 63, 78, 21, 2, 16 };
            byte[] key2 = { 158, 23, 64, 96, 57, 225, 36, 85 };
            byte[] key3 = { 49, 7, 210, 96, 13, 71, 62, 90 };

            CryptoSymmetric crypto = new Crypto3DES(key1, key2, key3);
            string originalMessage = "I love cryptography and TripleDES with three 64-bits keys";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }
    }
}

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PlainCrypto;

namespace PlainCryptoTest
{
    [TestClass]
    public class CryptoAES_Test
    {
        [TestMethod]
        public void CryptoAES128_EncryptionTest()
        {
            //Arrange
            byte[] key = { 16, 120, 8, 56, 24, 89, 74, 91, 150, 14, 52, 99, 203, 87, 247, 3 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and AES128";

            //Act
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
        }

        [TestMethod]
        public void CryptoAES128_DecryptionTest()
        {
            //Arrange
            byte[] key = { 16, 120, 8, 56, 24, 89, 74, 91, 150, 14, 52, 99, 203, 87, 247, 3 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and AES128";
            string encryptedMessage = "FOvwNOY/GxhWuB/3VkPoYWgoCb5zfFBUYwJ/CmJewLlcH9kaJTAISBFZXl/BvSff";

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoAES128_RoundTripTest()
        {
            //Arrange
            byte[] key = { 16, 120, 8, 56, 24, 89, 74, 91, 150, 14, 52, 99, 203, 87, 247, 3 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and AES128";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoAES192_EncryptionTest()
        {
            //Arrange
            byte[] key = { 11, 25, 3, 85, 201, 93, 102, 170, 27, 250, 231, 63, 74, 29, 14, 138, 64, 121, 227, 189, 42, 7, 52, 46 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and AES192";

            //Act
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
        }

        [TestMethod]
        public void CryptoAES192_DecryptionTest()
        {
            //Arrange
            byte[] key = { 11, 25, 3, 85, 201, 93, 102, 170, 27, 250, 231, 63, 74, 29, 14, 138, 64, 121, 227, 189, 42, 7, 52, 46 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and AES192";
            string encryptedMessage = "6GF6lFSPwPr4kOx5EPQgTUqI22AnafwZ/8zWys9FD1dtQOIvM74VbifyjkigRPoO";

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoAES192_RoundTripTest()
        {
            //Arrange
            byte[] key = { 11, 25, 3, 85, 201, 93, 102, 170, 27, 250, 231, 63, 74, 29, 14, 138, 64, 121, 227, 189, 42, 7, 52, 46 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and AES192";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoAES256_EncryptionTest()
        {
            //Arrange
            byte[] key = { 27, 1, 26, 2, 25, 3, 24, 4, 23, 5, 22, 255, 0, 75, 40, 63, 127, 40, 27, 18, 6, 21, 7, 20, 8, 18, 9, 19, 10, 17, 11, 16 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and the super secure AES256";

            //Act
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
        }

        [TestMethod]
        public void CryptoAES256_DecryptionTest()
        {
            //Arrange
            byte[] key = { 27, 1, 26, 2, 25, 3, 24, 4, 23, 5, 22, 255, 0, 75, 40, 63, 127, 40, 27, 18, 6, 21, 7, 20, 8, 18, 9, 19, 10, 17, 11, 16 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and the super secure AES256";
            string encryptedMessage = "d9XdMGjBZEcuhxLRIbVEPIYVE8QwZcDaMat675ZTQWwhn8D4sQyp75+16VWC3nCvexRtDH618NbhW3Q/KX04Pg==";

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void CryptoAES256_RoundTripTest()
        {
            //Arrange
            byte[] key = { 27, 1, 26, 2, 25, 3, 24, 4, 23, 5, 22, 255, 0, 75, 40, 63, 127, 40, 27, 18, 6, 21, 7, 20, 8, 18, 9, 19, 10, 17, 11, 16 };

            ICrypto crypto = new CryptoAES(key);
            string originalMessage = "I love cryptography and the super secure AES256";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }
    }
}

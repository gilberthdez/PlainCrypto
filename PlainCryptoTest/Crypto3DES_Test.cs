using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PlainCrypto;

namespace PlainCryptoTest
{
    [TestClass]
    public class Crypto3DES_Test
    {
        [TestMethod]
        public void Crypto3DES56_EncryptionTest()
        {
            //Arrange
            byte[] key = { 8, 207, 159, 63, 78, 21, 2, 16, 158, 23, 64, 96, 57, 225, 36, 85 };

            ICrypto crypto = new Crypto3DES(key);
            string originalMessage = "I love cryptography and 3DES with a 56 bit key";

            //Act
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
        }

        [TestMethod]
        public void Crypto3DES56_DecryptionTest()
        {
            ////Arrange
            //byte[] key = { 8, 207, 159, 63, 78, 21, 2, 16};

            //ICrypto crypto = new CryptoAES(key);
            //string originalMessage = "I love cryptography and 3DES with a 56 bit key";
            //string encryptedMessage = "FOvwNOY/GxhWuB/3VkPoYWgoCb5zfFBUYwJ/CmJewLlcH9kaJTAISBFZXl/BvSff";

            ////Act
            //string decryptedMessage = crypto.Decrypt(encryptedMessage);

            ////Assert
            //Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void Crypto3DES56_RoundTripTest()
        {
            //Arrange
            byte[] key = { 8, 207, 159, 63, 78, 21, 2, 16, 158, 23, 64, 96, 57, 225, 36, 85 };

            ICrypto crypto = new Crypto3DES(key);
            string originalMessage = "I love cryptography and 3DES with a 56 bit key";
            string encryptedMessage = crypto.Encrypt(originalMessage);

            //Act
            string decryptedMessage = crypto.Decrypt(encryptedMessage);

            //Assert
            Assert.AreNotEqual(originalMessage, encryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }
    }
}

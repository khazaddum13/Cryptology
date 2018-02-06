using Cryptology.BusinessServices.ALL;
using Cryptology.Model;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptology.BusinessServices
{
    public class AESSymmetricAlgorithmBuilder : SymmetricAlgorithmBuilder
    {
        public AESSymmetricAlgorithmBuilder() : base(SymmetricAlgorithmType.AES)
        {

        }
        public override string Decrypt(string cipherText, string secretKey)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                throw new ArgumentNullException("The string which needs to be decrypted can not be null.");
            }
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("Anahtar boş bırakılamaz");
            }

            byte[] cipherTextArr = Convert.FromBase64String(cipherText);
            byte[] secretKeyArr = ASCIIEncoding.ASCII.GetBytes(secretKey);

            AesCryptoServiceProvider serviceProvider = new AesCryptoServiceProvider();
            serviceProvider.Key = secretKeyArr;
            serviceProvider.Mode = CipherMode.CBC;
            serviceProvider.Padding = PaddingMode.PKCS7;

            var cryptoTransform = serviceProvider.CreateDecryptor(secretKeyArr, secretKeyArr);
            byte[] decrytedArr = cryptoTransform.TransformFinalBlock(cipherTextArr, 0, cipherTextArr.Length);

            return Convert.ToBase64String(decrytedArr);//ASCIIEncoding VE Base'i incele.
        }

        public override string Encrypt(string plainText, string secretKey)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException("");
            }
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("");
            }

            byte[] plainTextArr = Convert.FromBase64String(plainText);
            byte[] secretKeyArr = ASCIIEncoding.ASCII.GetBytes(secretKey);

            AesCryptoServiceProvider serviceProvider = new AesCryptoServiceProvider();
            serviceProvider.Key = secretKeyArr;
            serviceProvider.Mode = CipherMode.CBC;
            serviceProvider.Padding = PaddingMode.PKCS7;
            ICryptoTransform cryptoTransform = serviceProvider.CreateEncryptor(secretKeyArr, secretKeyArr);
            byte[] encryptedArr = cryptoTransform.TransformFinalBlock(plainTextArr, 0, plainTextArr.Length);

            serviceProvider.Clear();
            return Convert.ToBase64String(encryptedArr);
        }
    }
}

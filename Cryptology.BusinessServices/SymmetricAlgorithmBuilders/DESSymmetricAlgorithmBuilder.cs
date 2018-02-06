using Cryptology.BusinessServices.ALL;
using Cryptology.Model;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptology.BusinessServices
{
    public class DESSymmetricAlgorithmBuilder : SymmetricAlgorithmBuilder
    {
        public DESSymmetricAlgorithmBuilder() : base(SymmetricAlgorithmType.DES)
        {

        }
        public override string Decrypt(string cipherText, string secretKey)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                throw new ArgumentNullException("Decryption edilecek metin boş bırakılamaz!");
            }
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("Anahtar boş bırakılamaz!");
            }

            byte[] secretKeyArr = ASCIIEncoding.ASCII.GetBytes(secretKey);
            byte[] cipherTextArr = Convert.FromBase64String(cipherText);

            DESCryptoServiceProvider cryptoServiceProvider = new DESCryptoServiceProvider();

            MemoryStream memoryStream = new MemoryStream(cipherTextArr);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoServiceProvider.CreateDecryptor(secretKeyArr, secretKeyArr), CryptoStreamMode.Read);
            StreamReader streamReader = new StreamReader(cryptoStream);
            return streamReader.ReadToEnd();//////////////
        }

        public override string Encrypt(string plainText, string secretKey)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException("The string which needs to be encrypted can not be null.");
            }

            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("Anahtar boş bırakılamaz!");
            }
                                                                     
            byte[] secretKeyArr = ASCIIEncoding.ASCII.GetBytes(secretKey);
            byte[] plainTextArr = ASCIIEncoding.ASCII.GetBytes(plainText);

            DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();

            MemoryStream MemoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(MemoryStream, dESCryptoServiceProvider.CreateEncryptor(secretKeyArr, secretKeyArr), CryptoStreamMode.Write);

            cryptoStream.Write(plainTextArr, 0, plainTextArr.Length);
            cryptoStream.FlushFinalBlock();
            
            return Convert.ToBase64String(MemoryStream.GetBuffer(), 0, (int)MemoryStream.Length);////////////

            
        }
    }
}

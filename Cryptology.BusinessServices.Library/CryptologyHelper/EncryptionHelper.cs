using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptology.BusinessServices.Library
{
    public static class EncryptionHelper
    {
        #region Constants

        private const string cryptoKey = "cryptoKey";
        private const string privateKey = "<RSAKeyValue><Modulus>xF8uqCAIi3A+LJazyPmwt3vsdcOvFM5Ad80P3DTqqh2nnUHJcE7QYQ14t+pj06Pia8IebHVhb1g2kw4PvasAiShGzbFmJL8iv2f033JOWnO1Va4W3xloWCguLHQRSBOWCuqISoBuSh0AenErmaBr3IwIDBbUCZ6LYV838T4QEes=</Modulus><Exponent>AQAB</Exponent><P>9SWU1t9YZ1mvMWtC+B///kxZXMpXSqIX55UYUmKalEZWqA89xiTsG8FLt0PS0jHVqA36/SorfcKKN2VSrOuEFQ==</P><Q>zRDMzYW4rzKCFT1aZ0+6ygmrhYvfQk22UTMwhJx0fERHR2oBd0JgCjBLhqVxDQQd2s8gLAgaLmwUkM27XCS9/w==</Q><DP>YjOczPqJQlVl3ckW+ahv9uGExqvzjd0i8E0EgjQnsg//NLFuUIqH3pJvD0nnEPaPnROEoJec9nLQxWIcXVK3BQ==</DP><DQ>u3Fs0zw1GafAciu3tBGT+tOl/hdhhxjD2ytAYScl7uT2hpemKV35rbaBgt09HhmyNGz5ymXJkL9oeQglB8/p/w==</DQ><InverseQ>jTa8NieakJAc7qk7bwxNfneUsgvVf6PiB8tnE2LhXIJb5EDM8PHCwgDDOYYdnxLOEad7BcZ2i11fmrRGUOFw5A==</InverseQ><D>EECQa/m6u0+e1bHjT07bAVSQTW7UnrQzQbcHCQKYKVwq8yjuswzS0jV7OD195ZY6txBp1DAi0ERMv/757oiokowv78FjxWy+iSTYWt+U7UIRsW4rk8eMcl4N4LivOWi3GV3t8NCrU3mPEd68Lry+6XqIw0fni4ATjUdScDuCsIE=</D></RSAKeyValue>";

        // The Initialization Vector for the DES encryption routine
        private static readonly byte[] IV = new byte[8] { 240, 3, 45, 29, 0, 76, 173, 59 };

        #endregion Constants

        public static string MD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] retVal = md5.ComputeHash(Encoding.UTF8.GetBytes(input));

                StringBuilder sBuilder = new StringBuilder();
                for (int i = 0; i < retVal.Length; i++)
                {
                    sBuilder.Append(retVal[i].ToString("X2"));
                }
                return sBuilder.ToString();
            }
        }

        /// <summary>
        /// Encrypts provided string parameter
        /// </summary>
        /// <param name="input">String to encrypt</param>
        /// <returns>Encrypted string</returns>
        public static string Encrypt(string input)
        {
            if (!String.IsNullOrEmpty(input))
            {
                byte[] buffer = Encoding.UTF8.GetBytes(input);

                using (TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider())
                {
                    using (MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider())
                    {
                        des.Key = MD5.ComputeHash(ASCIIEncoding.UTF8.GetBytes(cryptoKey));
                        des.IV = IV;

                        return Convert.ToBase64String(des.CreateEncryptor().
                            TransformFinalBlock(buffer, 0, buffer.Length));
                    }
                }
            }

            return String.Empty;
        }

        /// <summary>
        /// Decrypts provided string parameter
        /// </summary>
        /// <param name="input">String to decrypt</param>
        /// <returns>Decrypted string</returns>
        public static string Decrypt(string input)
        {
            if (!String.IsNullOrEmpty(input))
            {
                byte[] buffer = Convert.FromBase64String(input);

                using (TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider())
                {
                    using (MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider())
                    {
                        des.Key = MD5.ComputeHash(ASCIIEncoding.UTF8.GetBytes(cryptoKey));
                        des.IV = IV;

                        return Encoding.ASCII.GetString(des.CreateDecryptor().
                            TransformFinalBlock(buffer, 0, buffer.Length));
                    }
                }
            }

            return String.Empty;
        }

        public static string RsaEncrypt(string inputString)
        {
            byte[] decryptedBytes = System.Text.Encoding.Unicode.GetBytes(inputString);

            //initialize cyripto service
            CspParameters cspParam = new CspParameters();
            cspParam.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(cspParam);
            RSA.FromXmlString(privateKey);
            byte[] encryptedBytes = RSA.Encrypt(decryptedBytes, false);
            return System.Convert.ToBase64String(encryptedBytes);
        }

        public static string RsaDecrypt(string inputString)
        {
            //initialize cyripto service
            CspParameters cspParam = new CspParameters();
            cspParam.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(cspParam);
            RSA.FromXmlString(privateKey);
            //Get encrypted smtp parameters
            byte[] encryptedBytes = System.Convert.FromBase64String(inputString);

            //Decrypt
            byte[] decryptedBytes = RSA.Decrypt(encryptedBytes, false);

            //get smptp paramters from decrypted byte array
            return System.Text.Encoding.Unicode.GetString(decryptedBytes);
        }

        public static string XOREncrypt(string plainText)
        {
            string cipherText = String.Empty;
            if (!String.IsNullOrEmpty(plainText))
            {
                byte[] decrypted = Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = new byte[decrypted.Length];

                for (int i = 0; i < decrypted.Length; i++)
                {
                    encrypted[i] = (byte)(decrypted[i] ^ cryptoKey[i % cryptoKey.Length]);
                }

                cipherText = Encoding.ASCII.GetString(encrypted);
            }

            return cipherText;
        }

        public static string XORDecrypt(string cipherText)
        {
            string plainText = String.Empty;
            if (!String.IsNullOrEmpty(cipherText))
            {
                byte[] encrypted = Encoding.UTF8.GetBytes(cipherText);
                byte[] decrypted = new byte[encrypted.Length];

                for (int i = 0; i < encrypted.Length; i++)
                {
                    decrypted[i] = (byte)(encrypted[i] ^ cryptoKey[i % cryptoKey.Length]);
                }

                plainText = Encoding.ASCII.GetString(decrypted);
            }
            return plainText;
        }
    }
}
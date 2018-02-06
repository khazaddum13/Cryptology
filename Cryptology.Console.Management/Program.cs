using Cryptology.BusinessServices;
using System;
using System.Configuration;

namespace Cryptology.Console.Management
{
    class Program
    {
        static void Main(string[] args)
        {
            AppSettingsReader settingsReader = new AppSettingsReader();
            string secretKey = settingsReader.GetValue("SecurityKeyForDES", typeof(string)).ToString();

            System.Console.WriteLine("Please enter the plain text For DES Alghoritms: ");
            string plainText = System.Console.ReadLine();

            SymmetricAlgorithmCreator creator = new SymmetricAlgorithmCreator();
            string cipherText = creator.CreateEncryption(new DESSymmetricAlgorithmBuilder(), plainText, secretKey);

            plainText = creator.CreateDecryption(new DESSymmetricAlgorithmBuilder(), cipherText, secretKey);

            System.Console.ForegroundColor = ConsoleColor.Yellow;


            System.Console.WriteLine("*////////////////////DES Alghoritm*////////////////////");
            System.Console.WriteLine("Plain Text: {0}", plainText);
            System.Console.WriteLine("Cipher Text: {0}", cipherText);
            System.Console.WriteLine("*////////////////////DES Alghoritm*////////////////////");

            System.Console.WriteLine("Please enter the plain text For Triple DES Alghoritms: ");
            plainText = System.Console.ReadLine();
            secretKey = settingsReader.GetValue("SecurityKeyForTripleDES", typeof(string)).ToString();

            cipherText = creator.CreateEncryption(new TripleDESSymmetricAlgorithmBuilder(), plainText, secretKey);

            plainText = creator.CreateDecryption(new TripleDESSymmetricAlgorithmBuilder(), cipherText, secretKey);


            System.Console.WriteLine("*////////////////////Triple DES Alghoritm*////////////////////");
            System.Console.WriteLine("Plain Text: {0}", plainText);
            System.Console.WriteLine("Cipher Text: {0}", cipherText);
            System.Console.WriteLine("*////////////////////Triple DES Alghoritm*////////////////////");

            System.Console.ReadLine();

        }
    }
}

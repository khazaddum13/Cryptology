using Cryptology.BusinessServices.ALL;

namespace Cryptology.BusinessServices
{
    public class SymmetricAlgorithmCreator
    {
        private SymmetricAlgorithmBuilder SymmetricAlgorithmBuilder;

        public string CreateEncryption(SymmetricAlgorithmBuilder symmetricAlgorithm, string plainText, string secretKey)
        {
            this.SymmetricAlgorithmBuilder = symmetricAlgorithm;
            return  SymmetricAlgorithmBuilder.Encrypt(plainText, secretKey);
        }

        public string CreateDecryption(SymmetricAlgorithmBuilder symmetricAlgorithm, string cipherText, string secretKey)
        {
            this.SymmetricAlgorithmBuilder = symmetricAlgorithm;
            return SymmetricAlgorithmBuilder.Decrypt(cipherText, secretKey);
        }
    }
}

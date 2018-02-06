using Cryptology.Model;

namespace Cryptology.BusinessServices.ALL
{
    public abstract class SymmetricAlgorithmBuilder
    {
        public abstract string Encrypt(string plainText, string secretKey);

        public abstract string Decrypt(string cipherText, string secretKey);

        private SymmetricAlgorithm symmetricAlgorithm;


        public SymmetricAlgorithmBuilder(SymmetricAlgorithmType symmetricAlgorithmType)
        {
            this.symmetricAlgorithm = new SymmetricAlgorithm(symmetricAlgorithmType);
        }

    }
}

namespace Cryptology.Model
{
    public enum SymmetricAlgorithmType
    {
        DES,
        TripleDES,
        AES ,
        RijndaelManaged
    }
    public class SymmetricAlgorithm
    {
        public string PlainText { get; set; }
        public string CipherText { get; set; }

        private SymmetricAlgorithmType symmetricAlgorithmType;
        public SymmetricAlgorithm(SymmetricAlgorithmType symmetricAlgorithmType)
        {
            this.symmetricAlgorithmType = symmetricAlgorithmType;
        }

        public string DisplayCipherText()
        {
            return this.CipherText;
        }

        public string DisplayPlainText()
        {
            return this.PlainText;
        }
    }
}

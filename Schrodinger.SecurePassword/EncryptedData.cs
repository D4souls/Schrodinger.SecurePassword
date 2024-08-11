namespace Schrodinger.SecurePassword
{
    public class EncryptedData
    {
        public string CipherText { get; set; } = null!;
        public byte[] Hash { get; set; }

        public EncryptedData(string _cipherText, byte[] _hash)
        {
            CipherText = _cipherText;
            Hash = _hash;
        }
    }
}

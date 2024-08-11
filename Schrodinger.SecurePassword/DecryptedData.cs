namespace Schrodinger.SecurePassword
{
    public class DecryptedData
    {
        public string PlainText { get; set; } = null!;
        public bool IsIntegrityVerified { get; set; }

        public DecryptedData(string plainText, bool isIntegrityVerified)
        {
            PlainText = plainText;
            IsIntegrityVerified = isIntegrityVerified;
        }
    }
}

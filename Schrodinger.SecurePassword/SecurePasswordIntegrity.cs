using System.Security.Cryptography;
using System.Text;

namespace Schrodinger.SecurePassword
{
    public static class SecurePasswordIntegrity
    {
        public static byte[] ComputeHash(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        public static bool VerifyHash(string input, byte[] hash)
        {
            byte[] computedHash = ComputeHash(input);
            return CryptographicOperations.FixedTimeEquals(computedHash, hash);
        }
    }
}

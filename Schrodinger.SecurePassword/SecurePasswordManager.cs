using System.Security.Cryptography;
using System.Text;

namespace Schrodinger.SecurePassword
{
    public class SecurePasswordManager
    {
        private readonly byte[] _key;

        public SecurePasswordManager(string secret)
        {
            _key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(secret));
        }

        public EncryptedData EncryptPassword(string plainText)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256;
                aesAlg.Key = _key;
                aesAlg.GenerateIV();
                byte[] iv = aesAlg.IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    msEncrypt.Write(iv, 0, iv.Length);

                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }

                    string cipherText = Convert.ToBase64String(msEncrypt.ToArray());

                    byte[] hash = SecurePasswordIntegrity.ComputeHash(plainText);

                    return new EncryptedData(cipherText, hash);
                }
            }
        }

        public DecryptedData DecryptPassword(EncryptedData encryptedData)
        {
            byte[] fullCipher = Convert.FromBase64String(encryptedData.CipherText);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = _key;

                // Extraemos el IV del texto cifrado
                byte[] iv = new byte[aesAlg.BlockSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);

                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    string plainText = srDecrypt.ReadToEnd();

                    // Comprobamos que el texto descifrado tenga el mismo hash
                    bool isIntegrityVerified = SecurePasswordIntegrity.VerifyHash(plainText, encryptedData.Hash);

                    return new DecryptedData(plainText, isIntegrityVerified);
                }
            }
        }
    }
}

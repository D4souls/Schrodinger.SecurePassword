using Schrodinger.SecurePassword;

public class Program
{
    static void Main(string[] args)
    {
        string secret = "tufG4m1ng";
        var manager = new SecurePasswordManager(secret);

        // Texto a cifrar
        string originalPassword = "MyT0y0t4SupraGoesBrrrrrr";

        // Cifrado de texto
        var encryptedPassword = manager.EncryptPassword(originalPassword);
        Console.WriteLine("Encrypted password: " + encryptedPassword.CipherText);
        Console.WriteLine("Encrypted password Hash: " + Convert.ToBase64String(encryptedPassword.Hash));

        // Descifrado de texto
        var decryptedPassword = manager.DecryptPassword(encryptedPassword);
        Console.WriteLine("Decrypted password: " + decryptedPassword.PlainText);
        Console.WriteLine("VerifiedIntegrity: " + decryptedPassword.IsIntegrityVerified);
    }
}
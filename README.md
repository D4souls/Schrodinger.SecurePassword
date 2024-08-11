# 🔒 Schrodinger.SecurePassword

![SecurePassword](https://github.com/user-attachments/assets/a90d6b1b-457f-4933-9fae-f453c14db66d)

## 📄 Description
Schrodinger.SecurePassword is a .NET library that provides secure methods for password encryption, decryption, and integrity verification. It combines AES (Advanced Encryption Standard) for encryption and SHA-256 for hashing, following the Encrypt-Then-MAC pattern to ensure both the confidentiality and integrity of passwords.

## ✨ Features

- **EncryptPassword:** Encrypts plaintext passwords using AES.
- **DecryptPassword:** Decrypts AES-encrypted passwords.
- **ComputeHash:** Generates a SHA-256 hash for integrity verification.
- **VerifyHash:** Verifies if the provided plaintext matches the hash.
- **Encrypt-Then-MAC:** Ensures both encryption and integrity verification using the AES + SHA-256 pattern.

## 💾 Installation

1. Clone the repository or download the DLL.
2. Add the DLL to your project: Right-click on "References" in Visual Studio, select "Add Reference...", and browse to the location of the Schrodinger.SecurePassword.dll.
3. Import the namespace: 
  ``` csharp
  using Schrodinger.SecurePassword;
  ```
## 📦 Usage
``` csharp
string secret = "MySecretPassphrase";
var manager = new SecurePasswordManager(secret);

// Encrypt the password
string originalPassword = "MySecurePassword123!";
EncryptedData encryptedData = manager.EncryptPassword(originalPassword);
Console.WriteLine($"Encrypted: {encryptedData.CipherText}");
Console.WriteLine($"Hash: {Convert.ToBase64String(encryptedData.Hash)}");

// Decrypt the password
DecryptedData decryptedData = manager.DecryptPassword(encryptedData);
Console.WriteLine($"Decrypted: {decryptedData.PlainText}");
Console.WriteLine($"Integrity Verified: {decryptedData.IsIntegrityVerified}");

```

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using RemoteDesktopCommon.Protocol;

namespace RemoteDesktopCommon.Security
{
    public class EncryptionHelper : IDisposable
    {
        private readonly ILogger<EncryptionHelper> _logger;
        private readonly Aes _aes;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public EncryptionHelper(ILogger<EncryptionHelper> logger, string encryptionKey = null)
        {
            _logger = logger;
            _aes = Aes.Create();
            _aes.KeySize = ProtocolConstants.AES_KEY_SIZE;
            _aes.BlockSize = ProtocolConstants.AES_BLOCK_SIZE;
            _aes.Mode = CipherMode.CBC;
            _aes.Padding = PaddingMode.PKCS7;

            if (string.IsNullOrEmpty(encryptionKey))
            {
                _key = GenerateRandomKey();
                _iv = GenerateRandomIV();
            }
            else
            {
                using (var deriveBytes = new Rfc2898DeriveBytes(encryptionKey, new byte[8], 1000, HashAlgorithmName.SHA256))
                {
                    _key = deriveBytes.GetBytes(_aes.KeySize / 8);
                    _iv = deriveBytes.GetBytes(_aes.BlockSize / 8);
                }
            }

            _aes.Key = _key;
            _aes.IV = _iv;
        }

        public byte[] Encrypt(byte[] data)
        {
            try
            {
                using (var msEncrypt = new MemoryStream())
                {
                    using (var encryptor = _aes.CreateEncryptor())
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, data.Length);
                        csEncrypt.FlushFinalBlock();
                    }

                    return msEncrypt.ToArray();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Encryption failed");
                throw;
            }
        }

        public byte[] Decrypt(byte[] encryptedData)
        {
            try
            {
                using (var msDecrypt = new MemoryStream(encryptedData))
                using (var decryptor = _aes.CreateDecryptor())
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var msPlain = new MemoryStream())
                {
                    csDecrypt.CopyTo(msPlain);
                    return msPlain.ToArray();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Decryption failed");
                throw;
            }
        }

        public string GetPublicKeyString()
        {
            return Convert.ToBase64String(_key);
        }

        private static byte[] GenerateRandomKey()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var key = new byte[ProtocolConstants.AES_KEY_SIZE / 8];
                rng.GetBytes(key);
                return key;
            }
        }

        private static byte[] GenerateRandomIV()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var iv = new byte[ProtocolConstants.AES_BLOCK_SIZE / 8];
                rng.GetBytes(iv);
                return iv;
            }
        }

        public void Dispose()
        {
            _aes?.Dispose();
            Array.Clear(_key, 0, _key.Length);
            Array.Clear(_iv, 0, _iv.Length);
        }

        public static class KeyExchange
        {
            public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
            {
                using (var rsa = new RSACryptoServiceProvider(2048))
                {
                    return (rsa.ExportRSAPublicKey(), rsa.ExportRSAPrivateKey());
                }
            }

            public static byte[] EncryptWithPublicKey(byte[] data, byte[] publicKey)
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportRSAPublicKey(publicKey, out _);
                    return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                }
            }

            public static byte[] DecryptWithPrivateKey(byte[] encryptedData, byte[] privateKey)
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                }
            }
        }
    }
}

using System;
using System.Security.Cryptography;
using System.Text;
using Qwerty.Encrypt.Demo;

namespace Core.Encrypt.demo
{
    class Program
    {
        static void Main(string[] args)
        {

            var privarteKey = "privateKey";
            var publicKey = "publicKey";
            var a = RsaEncrypt.RasSign("qwerty", privarteKey);
            var b = RsaEncrypt.VerifySign("qwerty", publicKey,a);


            var result = Encrypt("qwerty", "key");

            var content=AesDecrypt(result, "key");
            
        }
        public static string Encrypt(string content, string key)
        {
            byte[] keyArray = Convert.FromBase64String(key);
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(content);

            SymmetricAlgorithm des = Aes.Create();
            des.Key = keyArray;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = des.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray);
        }
        public static string AesDecrypt(string content, string key)
        {
            byte[] keyArray = Convert.FromBase64String(key);
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(content);

            SymmetricAlgorithm des = Aes.Create();
            des.Key = keyArray;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = des.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray);
        }
    }
}
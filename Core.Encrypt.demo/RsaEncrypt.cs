﻿using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Core.Encrypt.demo
{
    public static class RsaEncrypt
    {
        public static string RsaSign(string content, string privateKey)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA1withRSA");
            RsaPrivateCrtKeyParameters privateKeyParam =(RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            signer.Init(true, privateKeyParam);
            byte[] plainBytes = Encoding.UTF8.GetBytes(content);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            byte[] signBytes = signer.GenerateSignature();
            return Convert.ToBase64String(signBytes);
        }

        public static bool VerifySign(string content, string publicKey, string signData)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA1withRSA");
            RsaKeyParameters publicKeyParam =(RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            signer.Init(false, publicKeyParam);
            byte[] signBytes = Convert.FromBase64String(signData);
            byte[] plainBytes = Encoding.UTF8.GetBytes(content);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            bool ret = signer.VerifySignature(signBytes);
            return ret;
        }
    }
}

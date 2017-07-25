using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Qwerty.Encrypt.Demo
{
    public static class RsaEncrypt
    {
        public static string RasSign(string content, string privateKey)
        {
            var pkey = RSAPrivateKeyJava2DotNet(privateKey);
            string halg = "SHA1";//SHA1 MD5 SHA256  
            var  signData = RSAHelper.SignData(pkey, content, halg);//SHA1  
            return signData;
        }

        public static bool VerifySign(string content, string pubickKey, string sigdata)
        {
            var pkey = RSAPublicKeyJava2DotNet(pubickKey);
            string halg = "SHA1";//SHA1 MD5 SHA256  
            var signData = RSAHelper.VerifyData(pkey, content, sigdata, halg);//SHA1  
            return signData;
        }

        /// <summary>      
        /// RSA私钥格式转换，java->.net      
        /// </summary>      
        /// <param name="privateKey">java生成的RSA私钥</param>      
        /// <returns></returns>     
        private static string RSAPrivateKeyJava2DotNet(this string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
            Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }
        /// <summary>      
        /// RSA公钥格式转换，java->.net      
        /// </summary>      
        /// <param name="publicKey">java生成的公钥</param>      
        /// <returns></returns>      
        public static string RSAPublicKeyJava2DotNet(this string publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
        }
    }

    public class AsymmetricAlgorithmHelper<T> where T : AsymmetricAlgorithm, new()
    {
        protected static TResult Execute<TResult>(string key, Func<T, TResult> func)
        {
            using (T algorithm = new T())
            {
                algorithm.FromXmlString(key);
                return func(algorithm);
            }
        }
    
    }
    class RSAHelper : AsymmetricAlgorithmHelper<RSACryptoServiceProvider>
    {
        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="publickey">公钥</param>
        /// <param name="content">加密前的原始数据</param>
        /// <param name="fOAEP">如果为 true，则使用 OAEP 填充（仅在运行 Microsoft Windows XP 或更高版本的计算机上可用）执行直接的 System.Security.Cryptography.RSA加密；否则，如果为 false，则使用 PKCS#1 1.5 版填充。</param>
        /// <returns>加密后的结果（base64格式）</returns>
        public static string Encrypt(string publickey, string content, bool fOAEP = false)
        {
            return Execute(publickey,
                algorithm => Convert.ToBase64String(algorithm.Encrypt(Encoding.UTF8.GetBytes(content), fOAEP)));
        }
        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="privatekey">私钥</param>
        /// <param name="content">加密后的内容(base64格式)</param>
        /// <param name="fOAEP">如果为 true，则使用 OAEP 填充（仅在运行 Microsoft Windows XP 或更高版本的计算机上可用）执行直接的 System.Security.Cryptography.RSA加密；否则，如果为 false，则使用 PKCS#1 1.5 版填充。</param>
        /// <returns></returns>
        public static string Decrypt(string privatekey, string content, bool fOAEP = false)
        {
            return Execute(privatekey,
                algorithm => Encoding.UTF8.GetString(algorithm.Decrypt(Convert.FromBase64String(content), fOAEP)));
        }
        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="privatekey">私钥</param>
        /// <param name="content">需签名的原始数据(utf-8)</param>
        /// <param name="halg">签名采用的算法，如果传null，则采用MD5算法</param>
        /// <returns>签名后的值(base64格式)</returns>
        public static string SignData(string privatekey, string content, object halg = null)
        {
            return Execute(privatekey,
                algorithm => Convert.ToBase64String(algorithm.SignData(Encoding.UTF8.GetBytes(content), GetHalg(halg))));
        }
        /// <summary>
        /// RSA验签
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">需验证签名的数据(utf-8)</param>
        /// <param name="signature">需验证的签名字符串(base64格式)</param>
        /// <param name="halg">签名采用的算法，如果传null，则采用MD5算法</param>
        /// <returns></returns>
        public static bool VerifyData(string publicKey, string content, string signature, object halg = null)
        {
            return Execute(publicKey,
                algorithm => algorithm.VerifyData(Encoding.UTF8.GetBytes(content), GetHalg(halg), Convert.FromBase64String(signature)));
        }
        private static object GetHalg(object halg)
        {
            if (halg == null)
            {
                halg = "MD5";
            }
            return halg;
        }
       
    }
    public class DSAHelper : AsymmetricAlgorithmHelper<DSACryptoServiceProvider>
    {
        /// <summary>
        /// DSA签名
        /// </summary>
        /// <param name="privatekey">私钥</param>
        /// <param name="content">需签名的原始数据(utf-8)</param>
        /// <returns>签名后的值(base64格式)</returns>
        public static string SignData(string privatekey, string content)
        {
            return Execute(privatekey,
                algorithm => Convert.ToBase64String(algorithm.SignData(Encoding.UTF8.GetBytes(content))));
        }
        /// <summary>
        /// DSA验签
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">需验证签名的数据(utf-8)</param>
        /// <param name="signature">需验证的签名字符串(base64格式)</param>
        /// <returns></returns>
        public static bool VerifyData(string publicKey, string content, string signature)
        {
            return Execute(publicKey,
                algorithm => algorithm.VerifyData(Encoding.UTF8.GetBytes(content), Convert.FromBase64String(signature)));
        }
        
    }
}

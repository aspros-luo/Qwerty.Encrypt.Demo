using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Core.Encrypt.demo
{
    class Program
    {
        static void Main(string[] args)
        {
            var privateKey = @"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvbivgtzGJySaEgDINdwoiHmzI0Eb2qDOxwPpkeNPvOEUj713
BWTSZW77im4BE2d59+Dp1FxGq0e5bHdKdxZqmQq7VLLL+7PQMZJKEgnm4dzJhrCe
v6B0j9la6WtZNmVzfUR97x5xhn0JGajpGMF6iYILvf7T4LcTKrpY5M5IM2IgfE2T
qi7bLlV7RBXekYrEEMYEGWeGIXWyppuRDTb2RMgDiBTt0oPWXuI+w2cw2yestP3q
4KHez29DsPRQfFUM2Q43iWlfMrpEKB0HIBaBIlKmQ1H5vQX4U0zPPwqYE36QmPUJ
IWDu9qQIgDHl/N+wGtdxBIEcYOQqCqGt0lmwWQIDAQABAoIBAQCCf4HCOsfV7thH
X+BXI9uBnGx66HMXXBs/S1Ki9b9IRW4WPRWcUTBjcwZ0vpvg1AFSXpOYbexyLkC9
+gPvjCzAnmAir2Wd+Z5QKrbmV4dHfs3j5qMbXmwu8iwVeLCBuSDKXo1dKAygnGrh
Co1jaNo3sYsQIjNtU6BMeKdiov2I0Vr9XI2d/ER8vMOSIlYYKFoBW6CS5azdQtL3
8Mnx3khh01NKC82yhmBqgNj5KbLvPmg2H8AqLEcw+zevl1ruX6i62vcvvrY+T9Bf
1/aMRIIUTIOB6NV70HH4BMjDh+0Xf0rVTY/pTUR60IphJ4bC0a6vz8qQj0ESWC1G
EnToogq9AoGBAPCIV8JsC5dLMPJi9B0YTAf+wJ+Rg8VyUym7ACTPZaxDSUnZ3zYa
ktlqdtijMPYtI7E2eM4uenfwDvS9wd4IVPQSvmxfN0HTJBuhhSEhfLbu0hNX7FKu
GBAQZ66vnPf5xE8idB3yMK0KdlnA/VEcCeN8KdIGSolwjP7/0gQFVdYrAoGBAMnr
4yxv+3bySAJXObsZXBIudpLuJ3sW3ijLa55Kr0bQTNo2glD9nZfwVy9Yz09Crppa
cSeceZc9Cr76pzsotisDLhmwWumDa5LpMFdSXU6xA6xAMs0hvQHgU9JpLrX2QT3j
MiO2i2ZUZGXcFU7oBatyS3QAaXWNfef9ZLfN9rWLAoGBAMb9ZO0ZibVOpV3Bc4cm
dLAgl6brMYKFhDt/0yygz9JlkBoivsD51wc7RrsOtxDSYzbWg7a/SN40oYrj+aEA
b5fEcfkiBIrWbIbXZ1XzaEPG69DI6l+0W3/esogYDNoxrbByJnInzRE7GJJEUM1r
Ttr9+3MfdUai8GJ9rXdaGpslAoGANGx4y5W7TNN0XJ82ztuzqsjDYjxQpcV3IlJF
+4/aV+FGwrS6OrrNyp/Mku9Uy3g9ireGf0lBzEE94/2Bo3tbaGln86V0xQGo0TiX
o2Qv83lDwdndFqL2xmDugkdqqDVqFN5Cq0D+ii/I7SUppxXYOv3ulwxwVOPKV4vT
NWFU9ycCgYEAibn+OuX46Bs6cjDvkhl8BzturUhadbOTghS7qxSdq50pQMVmEuPU
rVo7Kd/1/j39go3RrW/OhT5QKbnqC9oGBkxGIfO254yqEbiuqOiv5oE2rpOlnWbd
2koW6F/DjYBaY6cJeQiR6pD8M/jv3faq4plv+e9HL/Zy+dJ6u0NhuZc=
-----END RSA PRIVATE KEY-----
";
            var publicKey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbivgtzGJySaEgDINdwo
iHmzI0Eb2qDOxwPpkeNPvOEUj713BWTSZW77im4BE2d59+Dp1FxGq0e5bHdKdxZq
mQq7VLLL+7PQMZJKEgnm4dzJhrCev6B0j9la6WtZNmVzfUR97x5xhn0JGajpGMF6
iYILvf7T4LcTKrpY5M5IM2IgfE2Tqi7bLlV7RBXekYrEEMYEGWeGIXWyppuRDTb2
RMgDiBTt0oPWXuI+w2cw2yestP3q4KHez29DsPRQfFUM2Q43iWlfMrpEKB0HIBaB
IlKmQ1H5vQX4U0zPPwqYE36QmPUJIWDu9qQIgDHl/N+wGtdxBIEcYOQqCqGt0lmw
WQIDAQAB
-----END PUBLIC KEY-----
";
            var xmlPrivatekey= RsaHelper.PrivateKeyPkcs1ToXml(privateKey);
            var javaPrivateKey =
                @"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPoCAUetNkbU6tnq4InnPJU5W1orIAGcC3h2Th28ePzzjFtUxXmUyLVmPe0gfmMH+AyD5Qhq4cpe2kO1diLYm1xDJ7OS2KeyU0VoUpz0XJfitqVz7IpzXN43Hy3t7yLqEsmB7iHOQQ0yWi6l5Y9/IRAbKDSl2AWizHuIKJiPaHhSwY7rfiWKZVSC2G3y46ol0mP2Czeurcqw45N74Man3NexvQi+2PPWqONW82rApypv2U1DYsb7sSqcrlELDDAUKYSDXwqWHfH/mGtPoej4WPUhg5J2ggO3jszuaj8sB8tnWqBOvZIWJKQDcnJKxghZZZANeAUPyC6UOPO2ZfPxolAgMBAAECggEBAMwuip3ZVH5UyKURgdDUEsYQvw/LGgXjTZSvP9Sl0JFqlkhITPVwusfkg36jSkVjuGArjKygZiWiQBvch8jzQ5RPh92Kk3C2PhZEZ9yAC/9lZsjDV+j4F3+Mh4jzCIletf4m82gmRVsOatrWZUZVP+bdpnJa9ay+AX+/whADc348/xuEfS2fBZ12ecyQvd3o9+4e5IWL0b6vTzhBr5R973uljErdeVZYyK1ykFPuCsdXAKLAz+1Myzr0i/Wa4dYqMfudPi+yBIsp3swmlnrLo790G+R4+g4kliyGPWHMDB/DqA+a5agMDGNZryIRqWo7XBet1wq88kUIgRdzPvrPAZkCgYEA/0bXOQv3/X7vdWrh1kj4eC5bAxTS7/Ojm82VYUbH3tkVW55JOQlCepCD5CNxkixoHT5JnhhRtM4NWXWyA5Ze+J96RmSdBI0xTiqn5pPtBFZxZPvKozsqRHs4z7rOI9FPHMWBf7G3vr8w59ziqtwFIR1BnGEjEr4TWayTEErsH38CgYEA0Da4ymLB+nIPMO17gryLuSLb0LRuAa9DVpX9IgAjSMtOZzZcVQkU+Wt19IQIpC8jEGCTuBviQCp5y4lydagR5UfYAntvsG9XAgWrPeDaIqyyKnymYKCYFlKypCAqmijyI9o+6Dza5ZHBpVeNnMU4On+K5mc1fOT9i+P1hROkGFsCgYAqcwtDDzxzyPHk4psfWQ8IXR0BTCsvf6JLPEqE3JJL+mlUzON8Oo/1daaY/1PZbMz7X+o6Ae1EVadeovWxJwYv7cUVg5GguiHiz7EP5LVbLUy58CzoK+SBcsQltvikeB/htu4r38+gRobJZ6/Bnci0kvrgGD8O1NC+7rWd1feh3QKBgQDJFnB1ldd9xzaArHsCkpHm5ZGiCP/NRLUmJIlqkvOA1EkOSWP3BGRrVqt+0R1/Y77bjEpeHx/tlJg4SLBwjTdrVm16SDhgD8faPhtaEZTatCsF+Yi9/Zukw42gESjT5gOlOJxUsqE94f1BcENmStq5NICzcK4pxwZQWoK+WW+7zQKBgDLi7ZtOyGDwbOSYwAAn/lCKxx8aMFTj1i4Ljlz+1YpH9ZeUVOoi4uCe9Z6zXOUQ9H35lMR1TlHgXx614SRo9mFu1XmKV85ekqy3aV5NUYDT5WAA65iPjqJbCSEk6kwz6Cb6ZZh/OhGnFtQo62bZ5dwiqtDtthit6FJlTzdaanlA";
            var xmlPublicKey = RsaHelper.PublicKeyPemToXml(publicKey);
            var sign = RsaHelper.RsaSign("123", false, xmlPrivatekey);
            var result = RsaHelper.ValidateRsaSign("123", false, xmlPublicKey, sign);
            Console.WriteLine(result);
        }
        public static class RsaHelper
        {
            /// <summary>
            /// private key sign
            /// </summary>
            /// <param name="preSign"></param>
            /// <param name="isJavaFormatKey"></param>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string RsaSign(string preSign, bool isJavaFormatKey, string privateKey)
            {
                try
                {
                    //// net
                    //var rsa = new RSACryptoServiceProvider();
                    //rsa.FromXmlString(privateKey);
                    //byte[] signBytes = rsa.SignData(UTF8Encoding.UTF8.GetBytes(signStr), "md5");
                    //return Convert.ToBase64String(signBytes);

                    // net core 2.0
                    using (var rsa = RSA.Create())
                    {
                        if (isJavaFormatKey) privateKey = RsaPrivateKeyJava2DotNet(privateKey);
                        FromXmlStringExtensions(rsa,privateKey);
                        var bytes = rsa.SignData(Encoding.UTF8.GetBytes(preSign), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        return Convert.ToBase64String(bytes);
                    }
                }
                catch (Exception e)
                {
                    throw new ArgumentException(e.Message);
                }
            }
            /// <summary>
            /// public key sign
            /// </summary>
            /// <param name="preSign"></param>
            /// <param name="publicKey"></param>
            /// <returns></returns>
            public static string RsaEncrypt(string preSign, string publicKey)
            {
                try
                {
                    //// net
                    //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    //rsa.FromXmlString(strPublicKey);
                    //byte[] bytes = rsa.Encrypt(UTF8Encoding.UTF8.GetBytes(strEncryptInfo), false);
                    //return Convert.ToBase64String(bytes);

                    // net core 2.0
                    using (var rsa = RSA.Create())
                    {
                        publicKey = RsaPublicKeyJava2DotNet(publicKey);
                        FromXmlStringExtensions(rsa,publicKey);
                        var bytes = rsa.Encrypt(Encoding.UTF8.GetBytes(preSign), RSAEncryptionPadding.Pkcs1);
                        return Convert.ToBase64String(bytes);
                    }
                }
                catch (Exception e)
                {
                    throw new ArgumentException(e.Message);
                }
            }
            /// <summary>
            /// public key validate
            /// </summary>
            /// <param name="preSign"></param>
            /// <param name="isJavaFormatKey"></param>
            /// <param name="publicKey"></param>
            /// <param name="signedData"></param>
            /// <returns></returns>
            public static bool ValidateRsaSign(string preSign, bool isJavaFormatKey, string publicKey, string signedData)
            {
                try
                {
                    //// net
                    //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    //rsa.FromXmlString(publicKey);
                    //return rsa.VerifyData(UTF8Encoding.UTF8.GetBytes(plainText), "md5", Convert.FromBase64String(signedData));

                    // net core 2.0
                    using (var rsa = RSA.Create())
                    {
                        if (isJavaFormatKey) publicKey = RsaPublicKeyJava2DotNet(publicKey);
                        FromXmlStringExtensions(rsa, publicKey);
                        return rsa.VerifyData(Encoding.UTF8.GetBytes(preSign), Convert.FromBase64String(signedData), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                }
                catch (Exception e)
                {
                    throw new ArgumentException(e.Message);
                }
            }
            /// <summary>
            /// private key ，java->.net
            /// </summary>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string RsaPrivateKeyJava2DotNet(string privateKey)
            {
                if (string.IsNullOrEmpty(privateKey))
                {
                    return string.Empty;
                }
                var privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
                return
                    $"<RSAKeyValue><Modulus>{Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned())}</Modulus><Exponent>{Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned())}</Exponent><P>{Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned())}</P><Q>{Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned())}</Q><DP>{Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned())}</DP><DQ>{Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned())}</DQ><InverseQ>{Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned())}</InverseQ><D>{Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned())}</D></RSAKeyValue>";
            }
            /// <summary>
            /// public key ，java->.net
            /// </summary>
            /// <param name="publicKey"></param>
            /// <returns>格式转换结果</returns>
            public static string RsaPublicKeyJava2DotNet(string publicKey)
            {
                if (string.IsNullOrEmpty(publicKey))
                {
                    return string.Empty;
                }

                var publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
                return string.Format(
                    "<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                    Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                    Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned())
                );
            }
            /// <summary>
            /// private key ，.net->java
            /// </summary>
            /// <param name="privateKey">.net生成的私钥</param>
            /// <returns></returns>
            public static string RsaPrivateKeyDotNet2Java(string privateKey)
            {
                var doc = new XmlDocument();
                doc.LoadXml(privateKey);
                var m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
                var exp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
                var d = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("D")[0].InnerText));
                var p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("P")[0].InnerText));
                var q = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Q")[0].InnerText));
                var dp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DP")[0].InnerText));
                var dq = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DQ")[0].InnerText));
                var qinv = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("InverseQ")[0].InnerText));

                var privateKeyParam = new RsaPrivateCrtKeyParameters(m, exp, d, p, q, dp, dq, qinv);

                var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
                var serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
                return Convert.ToBase64String(serializedPrivateBytes);
            }
            /// <summary>
            /// public key ，.net->java
            /// </summary>
            /// <param name="publicKey">.net生成的公钥</param>
            /// <returns></returns>
            public static string RsaPublicKeyDotNet2Java(string publicKey)
            {
                var doc = new XmlDocument();
                doc.LoadXml(publicKey);
                var m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
                var p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
                var pub = new RsaKeyParameters(false, m, p);

                var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
                var serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
                return Convert.ToBase64String(serializedPublicBytes);
            }
            // 处理 下面两种方式都会出现的 Operation is not supported on this platform 异常
            // RSA.Create().FromXmlString(privateKey) 
            // new RSACryptoServiceProvider().FromXmlString(privateKey) 
            /// <summary>
            /// 扩展FromXmlString
            /// </summary>
            /// <param name="rsa"></param>
            /// <param name="xmlString"></param>
            private static void FromXmlStringExtensions(RSA rsa, string xmlString)
            {
                var parameters = new RSAParameters();

                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(xmlString);

                if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
                {
                    foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                    {
                        switch (node.Name)
                        {
                            case "Modulus":
                                parameters.Modulus = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                            case "Exponent":
                                parameters.Exponent = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                            case "P":
                                parameters.P = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                            case "Q":
                                parameters.Q = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                            case "DP":
                                parameters.DP = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                            case "DQ":
                                parameters.DQ = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                            case "InverseQ":
                                parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                            case "D":
                                parameters.D = (string.IsNullOrEmpty(node.InnerText)
                                    ? null
                                    : Convert.FromBase64String(node.InnerText));
                                break;
                        }
                    }
                }
                else
                {
                    throw new Exception("Invalid XML RSA key.");
                }

                rsa.ImportParameters(parameters);
            }
            //        /// <summary>
            //        /// 扩展ToXmlString,创建公私钥
            //        /// </summary>
            //        /// <param name="includePrivateParameters"></param>
            //        /// <returns></returns>
            //        public static string ToCreateKey(bool includePrivateParameters)
            //        {
            //            using (var rsa = RSA.Create())
            //            {
            //                var parameters = rsa.ExportParameters(includePrivateParameters);
            //                return
            //                    $"<RSAKeyValue><Modulus>{(parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null)}</Modulus><Exponent>{(parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null)}</Exponent><P>{(parameters.P != null ? Convert.ToBase64String(parameters.P) : null)}</P><Q>{(parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null)}</Q><DP>{(parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null)}</DP><DQ>{(parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null)}</DQ><InverseQ>{(parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null)}</InverseQ><D>{(parameters.D != null ? Convert.ToBase64String(parameters.D) : null)}</D></RSAKeyValue>";
            //            }
            //        }
            /// <summary>
            /// Generate XML Format RSA Key. Result: Index 0 is the private key and index 1 is the public key
            /// </summary>
            /// <param name="keySize">Key Size.Unit: bits</param>
            /// <returns></returns>
            public static List<string> XmlKey(int keySize)
            {
                using (var rsa = RSA.Create())
                {
                    rsa.KeySize = keySize;
                    var rsap = rsa.ExportParameters(true);
                    var res = new List<string>();
                    var privatElement = new XElement("RSAKeyValue");
                    //Modulus
                    var primodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));
                    //Exponent
                    var priexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));
                    //P
                    var prip = new XElement("P", Convert.ToBase64String(rsap.P));
                    //Q
                    var priq = new XElement("Q", Convert.ToBase64String(rsap.Q));
                    //DP
                    var pridp = new XElement("DP", Convert.ToBase64String(rsap.DP));
                    //DQ
                    var pridq = new XElement("DQ", Convert.ToBase64String(rsap.DQ));
                    //InverseQ
                    var priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsap.InverseQ));
                    //D
                    var prid = new XElement("D", Convert.ToBase64String(rsap.D));

                    privatElement.Add(primodulus);
                    privatElement.Add(priexponent);
                    privatElement.Add(prip);
                    privatElement.Add(priq);
                    privatElement.Add(pridp);
                    privatElement.Add(pridq);
                    privatElement.Add(priinverseQ);
                    privatElement.Add(prid);

                    //添加私钥
                    res.Add(privatElement.ToString());

                    var publicElement = new XElement("RSAKeyValue");
                    //Modulus
                    var pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));
                    //Exponent
                    var pubexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));

                    publicElement.Add(pubmodulus);
                    publicElement.Add(pubexponent);

                    //添加公钥
                    res.Add(publicElement.ToString());

                    return res;
                }
            }
            /// <summary>
            /// Generate RSA key in Pkcs1 format. Result: Index 0 is the private key and index 1 is the public key
            /// </summary>
            /// <param name="keySize">Key Size.Unit: bits</param>
            /// <param name="format">Whether the format is true If it is standard pem file format</param>
            /// <returns></returns>
            public static List<string> Pkcs1Key(int keySize, bool format = true)
            {
                var res = new List<string>();

                var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
                kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
                var keyPair = kpGen.GenerateKeyPair();

                var sw = new StringWriter();
                var pWrt = new PemWriter(sw);
                pWrt.WriteObject(keyPair.Private);
                pWrt.Writer.Flush();
                var privateKey = sw.ToString();

                if (!format)
                {
                    privateKey = privateKey.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace("\r\n", "");
                }

                res.Add(privateKey);

                var swpub = new StringWriter();
                var pWrtpub = new PemWriter(swpub);
                pWrtpub.WriteObject(keyPair.Public);
                pWrtpub.Writer.Flush();
                var publicKey = swpub.ToString();
                if (!format)
                {
                    publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");
                }

                res.Add(publicKey);

                return res;
            }
            /// <summary>
            /// Generate Pkcs8 format RSA key. Result: Index 0 is the private key and index 1 is the public key
            /// </summary>
            /// <param name="keySize">Key Size.Unit: bits</param>
            /// <param name="format">Whether the format is true If it is standard pem file format</param>
            /// <returns></returns>
            public static List<string> Pkcs8Key(int keySize, bool format = true)
            {
                var res = new List<string>();

                var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
                kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
                var keyPair = kpGen.GenerateKeyPair();

                var swpri = new StringWriter();
                var pWrtpri = new PemWriter(swpri);
                var pkcs8 = new Pkcs8Generator(keyPair.Private);
                pWrtpri.WriteObject(pkcs8);
                pWrtpri.Writer.Flush();
                var privateKey = swpri.ToString();

                if (!format)
                {
                    privateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\r\n", "");
                }

                res.Add(privateKey);

                var swpub = new StringWriter();
                var pWrtpub = new PemWriter(swpub);
                pWrtpub.WriteObject(keyPair.Public);
                pWrtpub.Writer.Flush();
                var publicKey = swpub.ToString();
                if (!format)
                {
                    publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");
                }

                res.Add(publicKey);

                return res;
            }
            /// <summary>
            /// Public Key Convert xml->xml
            /// </summary>
            /// <param name="publicKey"></param>
            /// <returns></returns>
            public static string PublicKeyXmlToPem(string publicKey)
            {
                var root = XElement.Parse(publicKey);
                //Modulus
                var modulus = root.Element("Modulus");
                //Exponent
                var exponent = root.Element("Exponent");

                var rsaKeyParameters = new RsaKeyParameters(false, new BigInteger(1, Convert.FromBase64String(modulus?.Value)), new BigInteger(1, Convert.FromBase64String(exponent?.Value)));

                var sw = new StringWriter();
                var pWrt = new PemWriter(sw);
                pWrt.WriteObject(rsaKeyParameters);
                pWrt.Writer.Flush();
                return sw.ToString();
            }
            /// <summary>
            /// Private Key Convert xml->Pkcs1
            /// </summary>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string PrivateKeyXmlToPkcs1(string privateKey)
            {
                var root = XElement.Parse(privateKey);
                //Modulus
                var modulus = root.Element("Modulus");
                //Exponent
                var exponent = root.Element("Exponent");
                //P
                var p = root.Element("P");
                //Q
                var q = root.Element("Q");
                //DP
                var dp = root.Element("DP");
                //DQ
                var dq = root.Element("DQ");
                //InverseQ
                var inverseQ = root.Element("InverseQ");
                //D
                var d = root.Element("D");

                var rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, Convert.FromBase64String(modulus?.Value)),
                    new BigInteger(1, Convert.FromBase64String(exponent?.Value)),
                    new BigInteger(1, Convert.FromBase64String(d?.Value)),
                    new BigInteger(1, Convert.FromBase64String(p?.Value)),
                    new BigInteger(1, Convert.FromBase64String(q?.Value)),
                    new BigInteger(1, Convert.FromBase64String(dp?.Value)),
                    new BigInteger(1, Convert.FromBase64String(dq?.Value)),
                    new BigInteger(1, Convert.FromBase64String(inverseQ?.Value)));

                var sw = new StringWriter();
                var pWrt = new PemWriter(sw);
                pWrt.WriteObject(rsaPrivateCrtKeyParameters);
                pWrt.Writer.Flush();
                return sw.ToString();

            }
            /// <summary>
            /// Format public key
            /// </summary>
            /// <param name="str"></param>
            /// <returns></returns>
            private static string PublicKeyFormat(string str)
            {
                if (str.StartsWith("-----BEGIN PUBLIC KEY-----"))
                {
                    return str;
                }
                var res = new List<string> { "-----BEGIN PUBLIC KEY-----" };
                var pos = 0;
                while (pos < str.Length)
                {
                    var count = str.Length - pos < 64 ? str.Length - pos : 64;
                    res.Add(str.Substring(pos, count));
                    pos += count;
                }
                res.Add("-----END PUBLIC KEY-----");
                var resStr = string.Join("\r\n", res);
                return resStr;
            }
            /// <summary>
            /// Format Pkcs8 format private key
            /// </summary>
            /// <param name="str"></param>
            /// <returns></returns>
            private static string Pkcs8PrivateKeyFormat(string str)
            {
                if (str.StartsWith("-----BEGIN PRIVATE KEY-----"))
                {
                    return str;
                }
                var res = new List<string> { "-----BEGIN PRIVATE KEY-----" };
                var pos = 0;
                while (pos < str.Length)
                {
                    var count = str.Length - pos < 64 ? str.Length - pos : 64;
                    res.Add(str.Substring(pos, count));
                    pos += count;
                }
                res.Add("-----END PRIVATE KEY-----");
                var resStr = string.Join("\r\n", res);
                return resStr;
            }
            /// <summary>
            /// Format Pkcs1 format private key
            /// Author:Zhiqiang Li
            /// </summary>
            /// <param name="str"></param>
            /// <returns></returns>
            private static string Pkcs1PrivateKeyFormat(string str)
            {
                if (str.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
                {
                    return str;
                }
                var res = new List<string> { "-----BEGIN RSA PRIVATE KEY-----" };
                var pos = 0;
                while (pos < str.Length)
                {
                    var count = str.Length - pos < 64 ? str.Length - pos : 64;
                    res.Add(str.Substring(pos, count));
                    pos += count;
                }
                res.Add("-----END RSA PRIVATE KEY-----");
                var resStr = string.Join("\r\n", res);
                return resStr;
            }
            /// <summary>
            /// Remove the Pkcs8 format private key format
            /// </summary>
            /// <param name="str"></param>
            /// <returns></returns>
            private static string Pkcs8PrivateKeyFormatRemove(string str)
            {
                if (!str.StartsWith("-----BEGIN PRIVATE KEY-----"))
                {
                    return str;
                }
                return str.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "")
                    .Replace("\r\n", "");
            }
            /// <summary>
            /// public Key pem to xml
            /// </summary>
            /// <param name="publicKey"></param>
            /// <returns></returns>
            public static string PublicKeyPemToXml(string publicKey)
            {
                publicKey = PublicKeyFormat(publicKey);

                var pr = new PemReader(new StringReader(publicKey));
                var obj = pr.ReadObject();
                if (!(obj is RsaKeyParameters rsaKey))
                {
                    throw new Exception("Public key format is incorrect");
                }

                var publicElement = new XElement("RSAKeyValue");
                //Modulus
                var pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsaKey.Modulus.ToByteArrayUnsigned()));
                //Exponent
                var pubexponent = new XElement("Exponent", Convert.ToBase64String(rsaKey.Exponent.ToByteArrayUnsigned()));

                publicElement.Add(pubmodulus);
                publicElement.Add(pubexponent);
                return publicElement.ToString();
            }
            /// <summary>
            /// Private Key Convert Pkcs1->xml
            /// </summary>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string PrivateKeyPkcs1ToXml(string privateKey)
            {
                privateKey = Pkcs1PrivateKeyFormat(privateKey);

                var pr = new PemReader(new StringReader(privateKey));
                if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
                {
                    throw new Exception("Private key format is incorrect");
                }
                var rsaPrivateCrtKeyParameters =
                    (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(
                        PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));

                var privatElement = new XElement("RSAKeyValue");
                //Modulus
                var primodulus = new XElement("Modulus", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned()));
                //Exponent
                var priexponent = new XElement("Exponent", Convert.ToBase64String(rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned()));
                //P
                var prip = new XElement("P", Convert.ToBase64String(rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned()));
                //Q
                var priq = new XElement("Q", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned()));
                //DP
                var pridp = new XElement("DP", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned()));
                //DQ
                var pridq = new XElement("DQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned()));
                //InverseQ
                var priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned()));
                //D
                var prid = new XElement("D", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()));

                privatElement.Add(primodulus);
                privatElement.Add(priexponent);
                privatElement.Add(prip);
                privatElement.Add(priq);
                privatElement.Add(pridp);
                privatElement.Add(pridq);
                privatElement.Add(priinverseQ);
                privatElement.Add(prid);

                return privatElement.ToString();
            }
            /// <summary>
            /// Private Key Convert Pkcs8->xml
            /// </summary>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string PrivateKeyPkcs8ToXml(string privateKey)
            {
                privateKey = Pkcs8PrivateKeyFormatRemove(privateKey);
                var privateKeyParam =
                    (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

                var privatElement = new XElement("RSAKeyValue");
                //Modulus
                var primodulus = new XElement("Modulus", Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()));
                //Exponent
                var priexponent = new XElement("Exponent", Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()));
                //P
                var prip = new XElement("P", Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()));
                //Q
                var priq = new XElement("Q", Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()));
                //DP
                var pridp = new XElement("DP", Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()));
                //DQ
                var pridq = new XElement("DQ", Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()));
                //InverseQ
                var priinverseQ = new XElement("InverseQ", Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()));
                //D
                var prid = new XElement("D", Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));

                privatElement.Add(primodulus);
                privatElement.Add(priexponent);
                privatElement.Add(prip);
                privatElement.Add(priq);
                privatElement.Add(pridp);
                privatElement.Add(pridq);
                privatElement.Add(priinverseQ);
                privatElement.Add(prid);

                return privatElement.ToString();
            }
            /// <summary>
            /// Private Key Convert xml->Pkcs8
            /// </summary>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string PrivateKeyXmlToPkcs8(string privateKey)
            {
                var root = XElement.Parse(privateKey);
                //Modulus
                var modulus = root.Element("Modulus");
                //Exponent
                var exponent = root.Element("Exponent");
                //P
                var p = root.Element("P");
                //Q
                var q = root.Element("Q");
                //DP
                var dp = root.Element("DP");
                //DQ
                var dq = root.Element("DQ");
                //InverseQ
                var inverseQ = root.Element("InverseQ");
                //D
                var d = root.Element("D");

                var rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, Convert.FromBase64String(modulus?.Value)),
                    new BigInteger(1, Convert.FromBase64String(exponent?.Value)),
                    new BigInteger(1, Convert.FromBase64String(d?.Value)),
                    new BigInteger(1, Convert.FromBase64String(p?.Value)),
                    new BigInteger(1, Convert.FromBase64String(q?.Value)),
                    new BigInteger(1, Convert.FromBase64String(dp?.Value)),
                    new BigInteger(1, Convert.FromBase64String(dq?.Value)),
                    new BigInteger(1, Convert.FromBase64String(inverseQ?.Value)));

                var swpri = new StringWriter();
                var pWrtpri = new PemWriter(swpri);
                var pkcs8 = new Pkcs8Generator(rsaPrivateCrtKeyParameters);
                pWrtpri.WriteObject(pkcs8);
                pWrtpri.Writer.Flush();
                return swpri.ToString();

            }
            /// <summary>
            /// Private Key Convert Pkcs1->Pkcs8
            /// </summary>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string PrivateKeyPkcs1ToPkcs8(string privateKey)
            {
                privateKey = Pkcs1PrivateKeyFormat(privateKey);
                var pr = new PemReader(new StringReader(privateKey));

                var kp = pr.ReadObject() as AsymmetricCipherKeyPair;
                var sw = new StringWriter();
                var pWrt = new PemWriter(sw);
                var pkcs8 = new Pkcs8Generator(kp?.Private);
                pWrt.WriteObject(pkcs8);
                pWrt.Writer.Flush();
                var result = sw.ToString();
                return result;
            }
            /// <summary>
            /// Private Key Convert Pkcs8->Pkcs1
            /// </summary>
            /// <param name="privateKey"></param>
            /// <returns></returns>
            public static string PrivateKeyPkcs8ToPkcs1(string privateKey)
            {
                privateKey = Pkcs8PrivateKeyFormat(privateKey);
                var pr = new PemReader(new StringReader(privateKey));

                var kp = pr.ReadObject() as RsaPrivateCrtKeyParameters;

                var keyParameter = PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp));

                var sw = new StringWriter();
                var pWrt = new PemWriter(sw);
                pWrt.WriteObject(keyParameter);
                pWrt.Writer.Flush();
                var result = sw.ToString();
                return result;
            }
        }
    }

}

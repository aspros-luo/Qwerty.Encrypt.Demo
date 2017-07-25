using System.Collections.Generic;
using java.security;
using java.security.interfaces;
using java.security.spec;

namespace Qwerty.Encrypt.Demo
{
    public class JavatoCSharpRSAUtil
    {
        /// <summary>
        /// 数字签名
        /// 密钥算法
        /// </summary>
        public const string KEY_ALGORITHM = "RSA";

        /// <summary>
        /// 数字签名
        /// 签名/验证算法
        /// </summary>
        public const string SIGNATURE_ALGORITHM = "SHA1withRSA";

        /// <summary>
        /// 公钥
        /// </summary>
        private const string PUBLIC_KEY = "RSAPublicKey";

        /// <summary>
        /// 私钥
        /// </summary>
        private const string PRIVATE_KEY = "RSAPrivateKey";

        /// <summary>
        /// RSA密钥长度 默认1024位，
        ///  密钥长度必须是64的倍数， 
        ///  范围在512至65536位之间。
        /// </summary>
        private const int KEY_SIZE = 512;

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="data">
        ///            待签名数据 </param>
        /// <param name="privateKey">
        ///            私钥 </param>
        /// <returns> byte[] 数字签名 </returns>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static byte[] sign(byte[] data, byte[] privateKey) throws Exception
        public static byte[] sign(byte[] data, byte[] privateKey)
        {

            // 转换私钥材料
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);

            // 实例化密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

            // 取私钥匙对象
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

            // 实例化Signature
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);

            // 初始化Signature
            signature.initSign(priKey);

            // 更新
            signature.update(data);

            // 签名
            return signature.sign();
        }

        /// <summary>
        /// 校验
        /// </summary>
        /// <param name="data">
        ///            待校验数据 </param>
        /// <param name="publicKey">
        ///            公钥 </param>
        /// <param name="sign">
        ///            数字签名
        /// </param>
        /// <returns> boolean 校验成功返回true 失败返回false </returns>
        /// <exception cref="Exception">
        ///  </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static boolean verify(byte[] data, byte[] publicKey, byte[] sign) throws Exception
        public static bool verify(byte[] data, byte[] publicKey, byte[] sign)
        {

            // 转换公钥材料
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);

            // 实例化密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

            // 生成公钥
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            // 实例化Signature
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);

            // 初始化Signature
            signature.initVerify(pubKey);

            // 更新
            signature.update(data);

            // 验证
            return signature.verify(sign);
        }

        /// <summary>
        /// 取得私钥
        /// </summary>
        /// <param name="keyMap">
        /// @return </param>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static byte[] getPrivateKey(java.util.Map<String, Object> keyMap) throws Exception
        public static byte[] getPrivateKey(IDictionary<string, object> keyMap)
        {

            Key key = (Key)keyMap[PRIVATE_KEY];

            return key.getEncoded();
        }

        /// <summary>
        /// 取得公钥
        /// </summary>
        /// <param name="keyMap">
        /// @return </param>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static byte[] getPublicKey(java.util.Map<String, Object> keyMap) throws Exception
        public static byte[] getPublicKey(IDictionary<string, object> keyMap)
        {

            Key key = (Key)keyMap[PUBLIC_KEY];

            return key.getEncoded();
        }

        /// <summary>
        /// 初始化密钥
        /// </summary>
        /// <returns> Map 密钥对儿 Map </returns>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static java.util.Map<String, Object> initKey() throws Exception
        public static IDictionary<string, object> initKey()
        {

            // 实例化密钥对儿生成器
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);

            // 初始化密钥对儿生成器
            keyPairGen.initialize(KEY_SIZE);

            // 生成密钥对儿
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // 公钥
            RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();

            // 私钥
            RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

            // 封装密钥
            IDictionary<string, object> keyMap = new Dictionary<string, object>(2);

            keyMap[PUBLIC_KEY] = publicKey;
            keyMap[PRIVATE_KEY] = privateKey;

            return keyMap;
        }
    }
}
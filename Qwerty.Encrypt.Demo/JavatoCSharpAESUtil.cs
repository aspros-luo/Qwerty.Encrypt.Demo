using java.security;
using javax.crypto;
using javax.crypto.spec;

namespace Qwerty.Encrypt.Demo
{
    public class JavatoCSharpAESUtil
    {
        /// <summary>
        /// 密钥算法
        /// </summary>
        public const string KEY_ALGORITHM = "AES";

        /// <summary>
        /// 加密/解密算法 / 工作模式 / 填充方式 
        /// Java 6支持PKCS5Padding填充方式 
        /// Bouncy Castle支持PKCS7Padding填充方式
        /// </summary>
        public const string CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding"; //DES/ECB/NoPadding  AES/ECB/PKCS5Padding

        /// <summary>
        /// 转换密钥
        /// </summary>
        /// <param name="key"> 二进制密钥 </param>
        /// <returns> Key 密钥 </returns>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: private static java.security.Key toKey(byte[] key) throws Exception
        private static Key toKey(byte[] key)
        {

            // 实例化AES密钥材料
            SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

            return secretKey;
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="data"> 待解密数据 </param>
        /// <param name="key"> 密钥 </param>
        /// <returns> byte[] 解密数据 </returns>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static byte[] decrypt(byte[] data, byte[] key) throws Exception
        public static byte[] decrypt(byte[] data, byte[] key)
        {

            // 还原密钥
            Key k = toKey(key);

            /*
             * 实例化 
             * 使用PKCS7Padding填充方式，按如下方式实现 
             * Cipher.getInstance(CIPHER_ALGORITHM, "BC");
             */
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

            // 初始化，设置为解密模式
            cipher.init(Cipher.DECRYPT_MODE, k);

            // 执行操作
            return cipher.doFinal(data);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="data"> 待加密数据 </param>
        /// <param name="key"> 密钥 </param>
        /// <returns> byte[] 加密数据 </returns>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static byte[] encrypt(byte[] data, byte[] key) throws Exception
        public static byte[] encrypt(byte[] data, byte[] key)
        {

            // 还原密钥
            Key k = toKey(key);

            /*
             * 实例化 
             * 使用PKCS7Padding填充方式，按如下方式实现
             * Cipher.getInstance(CIPHER_ALGORITHM, "BC");
             */
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

            // 初始化，设置为加密模式
            cipher.init(Cipher.ENCRYPT_MODE, k);

            // 执行操作
            return cipher.doFinal(data);
        }

        /// <summary>
        /// 生成密钥 <br>
        /// </summary>
        /// <returns> byte[] 二进制密钥 </returns>
        /// <exception cref="Exception"> </exception>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public static byte[] initKey() throws Exception
        public static byte[] initKey()
        {

            // 实例化
            KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);

            /*
             * AES 要求密钥长度为 128位、192位或 256位
             */
            kg.init(128);

            // 生成秘密密钥
            SecretKey secretKey = kg.generateKey();

            // 获得密钥的二进制编码形式
            return secretKey.getEncoded();
        }
    }
}
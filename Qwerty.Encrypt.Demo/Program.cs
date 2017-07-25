using System;
using System.Text;

namespace Qwerty.Encrypt.Demo
{
    class Program
    {
        static void Main(string[] args)
        {

            //byte[] bycontent = Encoding.UTF8.GetBytes("qwerty");
            //byte[] bykey = Convert.FromBase64String("key");
            //byte[] data = JavatoCSharpAESUtil.encrypt(bycontent, bykey);
            //string encryptData = Convert.ToBase64String(data);


            //byte[] bycontent1 = Convert.FromBase64String(encryptData);
            //byte[] bykey1 = Convert.FromBase64String("key");
            //byte[] data1 = JavatoCSharpAESUtil.decrypt(bycontent1, bykey1);
            //string encryptData1 = Convert.ToBase64String(data1);


            //var result = AesEncrpt.Encrypt("qwerty", "key");

            //var content = AesEncrpt.Decrypt(result, "key");
            //var compare = encryptData == result;
            //var compare1 = encryptData1 == content;

            var privarteKey = "privateKey";
            var publicKey = "publicKey";
            byte[] bycontent = Encoding.UTF8.GetBytes("qwerty");
            byte[] byprivateKey = Convert.FromBase64String(privarteKey);
            byte[] sign = JavatoCSharpRSAUtil.sign(bycontent, byprivateKey);
            string result = Convert.ToBase64String(sign);

            var a = RsaEncrypt.RasSign("qwerty", privarteKey);


            var bycontent1 = Encoding.UTF8.GetBytes("qwerty");
            var bypublicKey = Convert.FromBase64String(publicKey);
            var sign1 = Convert.FromBase64String(result);

            //var b= JavatoCSharpRSAUtil.verify(bycontent1, bypublicKey, sign1);

            var c = RsaEncrypt.VerifySign("qwerty", publicKey, result);
        }
    }
}

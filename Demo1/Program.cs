using Qwerty.Encrypt.Demo;
using System;

namespace Demo1
{
    class Program
    {
        static void Main(string[] args)
        {
            var privarteKey = "privateKey";
            var publicKey = "publicKey";
            var a = RsaEncrypt.RasSign("qwerty", privarteKey);
            Console.WriteLine("Hello World!");
        }
    }
}
﻿using System;
using Core.Encrypt.demo;

namespace Demo1
{
    class Program
    {
        static void Main(string[] args)
        {
            var privarteKey = "privateKey";
            var publicKey = "publicKey";
            var a = RsaEncrypt.RsaSign("qwerty", privarteKey);
            Console.WriteLine("Hello World!");
        }
    }
}
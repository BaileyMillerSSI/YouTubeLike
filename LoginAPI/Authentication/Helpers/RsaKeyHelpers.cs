using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace LoginAPI.Authentication.Helpers
{
    public static class RsaKeyHelpers
    {
        public static (String PrivateKey, String PublicKey) GenerateKeys()
        {
            //Generate a public/private key pair.  
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //Save the public key information to an RSAParameters structure.  
            RSAParameters RSAKeyInfo = RSA.ExportParameters(true);

            var PrivateXML = RSA.ToXmlString(true);
            var PublicXML = RSA.ToXmlString(false);


            return (PrivateXML, PublicXML);
        }

        public static Task<(String PrivateKey, String PublicKey)> GenerateKeysAsync()
        {
            return Task.Run(()=> GenerateKeys());
        }
    }
}

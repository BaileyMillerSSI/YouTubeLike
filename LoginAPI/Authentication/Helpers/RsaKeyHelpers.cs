using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace LoginAPI.Authentication.Helpers
{
    public class RsaKeyHelpers
    {
        IHostingEnvironment Env;
        IConfiguration Configuration;
        public RsaKeyHelpers(IHostingEnvironment env, IConfiguration config)
        {
            Env = env;
            Configuration = config;
        }

        public (String PrivateKey, String PublicKey) TryGetOrGenerateKeys()
        {
            var privateKey = "";
            var publicKey = "";

            var Keys = RsaKeyHelpers.GenerateKeys();
            var dir = Directory.CreateDirectory(Path.Combine(Env.WebRootPath, "app", "keys"));
            using (var keyRef = File.Open(Path.Combine(dir.FullName, Configuration.GetSection("Keys:Public").Value), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
            {
                if (keyRef.Length == 0)
                {
                    var buf = Encoding.UTF8.GetBytes(Keys.PublicKey);
                    keyRef.Write(buf, 0, buf.Length);
                    keyRef.Flush();
                    keyRef.Seek(0, SeekOrigin.Begin);
                }
                using (var reader = new StreamReader(keyRef))
                {
                    publicKey = reader.ReadToEnd();
                }
            }

            using (var keyRef = File.Open(Path.Combine(dir.FullName, Configuration.GetSection("Keys:Private").Value), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
            {
                if (keyRef.Length == 0)
                {
                    var buf = Encoding.UTF8.GetBytes(Keys.PrivateKey);
                    keyRef.Write(buf, 0, buf.Length);
                    keyRef.Flush();
                    keyRef.Seek(0, SeekOrigin.Begin);
                }
                using (var reader = new StreamReader(keyRef))
                {
                    privateKey = reader.ReadToEnd();
                }
            }

            return (privateKey, publicKey);
        }

        public static (String PrivateKey, String PublicKey) GenerateKeys()
        {
            //Generate a public/private key pair.  
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //Save the public key information to an RSAParameters structure.  
            RSAParameters RSAKeyInfo = RSA.ExportParameters(true);

            var PrivateXML = RSA.ToxmlString(true);
            var PublicXML = RSA.ToxmlString(false);


            return (PrivateXML, PublicXML);
        }

        public static Task<(String PrivateKey, String PublicKey)> GenerateKeysAsync()
        {
            return Task.Run(()=> GenerateKeys());
        }
    }

    public static class XmlOverrides
    {
        public static void FromxmlString(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToxmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }
}

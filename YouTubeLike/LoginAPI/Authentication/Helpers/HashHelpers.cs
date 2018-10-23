using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace LoginAPI.Authentication.Helpers
{
    /// <summary>
    /// Provides functions to hash a password in a secure method
    /// </summary>
    public static class HashHelpers
    {
        /// <summary>
        /// Salt size in bytes
        /// </summary>
        const int SaltSize = 64 * 8;

        /// <summary>
        /// Key size in bytes
        /// </summary>
        const int KeySize = 256 * 8;
        public static bool VerifiyPassword(String InputPassword, byte[] OriginalSalt, String DB_Hash)
        {
            var GenerateNewHash = GenerateHash(InputPassword, OriginalSalt);

            return DB_Hash.Equals(GenerateNewHash);
        }


        private static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        public static String GenerateHash(String RawPassword, byte[] Salt, int Iterations = 100000, KeyDerivationPrf PRF = KeyDerivationPrf.HMACSHA512)
        {
            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: RawPassword,
                salt: Salt,
                prf: PRF,
                iterationCount: Iterations,
                numBytesRequested: KeySize));
        }

        public static (byte[] Salt, String Hash) GenerateHash(String RawPassword, int Iterations = 100000, KeyDerivationPrf PRF = KeyDerivationPrf.HMACSHA512)
        {
            var Salt = GenerateSalt();

            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            string Hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: RawPassword,
                salt: Salt,
                prf: PRF,
                iterationCount: Iterations,
                numBytesRequested: KeySize));


            return (Salt, Hash);
        }
    }
}

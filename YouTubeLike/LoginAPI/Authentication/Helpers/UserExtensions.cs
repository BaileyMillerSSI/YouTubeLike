using LoginAPI.Authentication.Tables;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginAPI.Authentication.Helpers
{
    public static class UserExtensions
    {
        public async static Task<(String Hash, Byte[] Salt)> GetUserHashInformation(this IdentityContext DB, String Email)
        {
            var hashInfo = await DB.Users
                .Where(x => x.Email == Email)
                .Select(x => x.Credentials)
                .Select(x => new
                {
                    x.SecurityHash,
                    x.SecuritySalt
                }).FirstOrDefaultAsync();

            if (hashInfo != null)
            {
                return (hashInfo.SecurityHash, Convert.FromBase64String(hashInfo.SecuritySalt));
            }
            else
            {
                return (String.Empty, new byte[0]);
            }
        }

        public async static Task<bool> VerifiyPassword(this IdentityContext DB, String Email, String InputPassword)
        {
            var hashInfo = await GetUserHashInformation(DB, Email);

            return HashHelpers.VerifiyPassword(InputPassword, hashInfo.Salt, hashInfo.Hash);

        }
    }
}

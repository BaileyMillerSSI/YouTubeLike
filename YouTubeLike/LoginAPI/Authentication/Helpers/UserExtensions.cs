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
        public async static Task<(String Hash, Byte[] Salt)> GetUserHashInformationAsync(this IdentityContext DB, String Email)
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

        public async static Task<bool> VerifiyPasswordAsync(this IdentityContext DB, String Email, String InputPassword)
        {
            var hashInfo = await GetUserHashInformationAsync(DB, Email);

            return HashHelpers.VerifiyPassword(InputPassword, hashInfo.Salt, hashInfo.Hash);

        }
    }
}

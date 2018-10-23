using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginAPI.Authentication.Tables
{
    public class UserSecurity
    {
        public int UserSecurityId { get; set; }
        public User User { get; set; }
        public int UserId { get; set; }

        public bool EmailVerified { get; set; } = false;

        public string SecurityHash { get; set; }
        public string SecuritySalt { get; set; }

        public DateTime PasswordIssuedAtUTC { get; set; } = DateTime.UtcNow;
        public int? PasswordChangeInterval { get; set; }
        
        public DateTime? DateLastAccessed { get; set; }
    }
}

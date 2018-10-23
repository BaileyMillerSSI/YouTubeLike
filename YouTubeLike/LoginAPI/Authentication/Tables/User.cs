using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginAPI.Authentication.Tables
{
    public class User
    {
        public int UserId { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public String MiddleInit { get; set; }
        public string LastName { get; set; }
        public DateTime DateCreatedUTC { get; set; } = DateTime.UtcNow;
        public List<UserRole> Roles { get; set; } = new List<UserRole>();

        public UserSecurity Credentials { get; set; }
        public int CredentialsId { get; set; }
    }
}

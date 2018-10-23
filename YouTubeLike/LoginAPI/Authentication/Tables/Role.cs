using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginAPI.Authentication.Tables
{
    public class Role
    {
        public int RoleId { get; set; }
        public String Description { get; set; }
        public Nullable<int> Priority { get; set; } = 1;
        public List<UserRole> Users { get; set; } = new List<UserRole>();
    }
}

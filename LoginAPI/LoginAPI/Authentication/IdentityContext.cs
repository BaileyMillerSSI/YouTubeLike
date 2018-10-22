using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginAPI.Authentication
{
    public class IdentityContext : DbContext
    {
        public IdentityContext(DbContextOptions<IdentityContext> options) 
            : base(options)
        {

        }
    }
}

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using plainAuth.models;
using plainAuth.models.UMC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace plainAuth.Context
{
    public class ApplicationDbContext : IdentityDbContext<UserModel>
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {
        }

    }
}

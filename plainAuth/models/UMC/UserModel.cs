using Microsoft.AspNetCore.Identity;
using plainAuth.models.UMC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace plainAuth.models
{
    public class UserModel : IdentityUser
    {

        public string FullName { get; set; }

        public string LastName { get; set; }
        public string Password { get; set; }

        public Tenant tenant { get; set; }

    }

    public class UserModelRole : UserModel
    { 
        public string Role { get; set; }
    }
}

using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace plainAuth.models
{
    public class UserModel : IdentityUser
    {

        public string FullName { get; set; }

        public string   LastName { get; set; }

        public string MyID { get; set; }

        public string expass { get; set; }

    }
}

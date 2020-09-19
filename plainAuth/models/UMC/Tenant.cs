using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace plainAuth.models.UMC
{
    public class Tenant 
    {
        [Key]
        public int TenantID { get; set; }
        public string TenantName { get; set; }
        public Address Address { get; set; }
        public List<UserModel> userModels { get; set; }
    }

    public class Address
    { 
        public int AddressID { get; set; }
        public string PrimaryAddress { get; set; }
        public string PinCode { get; set;}
    }
}

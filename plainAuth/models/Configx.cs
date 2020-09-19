using IdentityModel;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static IdentityModel.OidcConstants;
using GrantTypes = IdentityServer4.Models.GrantTypes;

namespace plainAuth.models
{
    public static class Configx
    {
        public static IEnumerable<ApiResource> Apis =>
            new List<ApiResource>
            {
            new ApiResource("api1", "My API")
            };
      public static IEnumerable<Client> Clients =>
    new List<Client>
    {
        new Client
        {
            ClientId = "client",

            // no interactive user, use the clientid/secret for authentication
            AllowedGrantTypes =GrantTypes.ClientCredentials ,

            // secret for authentication
            ClientSecrets =
            {
                new Secret("secret".ToSha256())
            },

            // scopes that client has access to
            AllowedScopes = { "api1" }
        }
    };
    }
}

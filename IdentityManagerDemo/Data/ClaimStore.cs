using System.Security.Claims;

namespace IdentityManagerDemo.Data
{
    public static class ClaimStore
    {
        public static List<Claim> ClaimsList = new List<Claim>()
        {
            new Claim("Create","Create"),
            new Claim("Edit","Edit"),
            new Claim("Delete","Delete")
        };
    }
}

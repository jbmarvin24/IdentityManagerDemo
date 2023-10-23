using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace IdentityManagerDemo.Models
{
    public class TwoFactorAuthenticationViewModel
    {
        //used to login
        public string Code { get; set; }

        //used to register / signup
        public string Token { get; set; }

        [ValidateNever]
        public string QRCodeUrl { get; set; }
    }
}

using System.ComponentModel.DataAnnotations;

namespace IdentityManagerDemo.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}

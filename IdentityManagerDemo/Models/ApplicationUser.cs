using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityManagerDemo.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }

        [NotMapped]
        public string RoleId { get; set; }

        [ValidateNever]
        [NotMapped]
        public string Role { get; set; }

        [ValidateNever]
        [NotMapped]
        public IEnumerable<SelectListItem> RoleList { get; set; }
    }
}

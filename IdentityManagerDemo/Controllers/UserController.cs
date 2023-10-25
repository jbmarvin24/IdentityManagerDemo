using IdentityManagerDemo.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManagerDemo.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext db;
        private readonly UserManager<IdentityUser> userManager;

        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            this.db=db;
            this.userManager=userManager;
        }
        public IActionResult Index()
        {
            var userList = db.ApplicationUser.ToList();
            var userRole = db.UserRoles.ToList();
            var roles = db.Roles.ToList();

            foreach (var user in userList)
            {
                var role = userRole.FirstOrDefault(u => u.UserId == user.Id);
                if (role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId).Name;
                }
            }

            return View(userList);
        }
    }
}

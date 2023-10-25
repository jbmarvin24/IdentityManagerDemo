using IdentityManagerDemo.Data;
using IdentityManagerDemo.Models;
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

        public IActionResult Edit(string userId)
        {
            var objFromDb = db.ApplicationUser.FirstOrDefault(u => u.Id==userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            var userRole = db.UserRoles.ToList();
            var roles = db.Roles.ToList();
            var role = userRole.FirstOrDefault(u => u.UserId == objFromDb.Id);
            if (role != null)
            {
                objFromDb.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId).Id;
            }
            objFromDb.RoleList = db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(objFromDb);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if (ModelState.IsValid)
            {
                var objFromDb = db.ApplicationUser.FirstOrDefault(u => u.Id == user.Id);
                if (objFromDb == null)
                {
                    return NotFound();
                }
                var userRole = db.UserRoles.FirstOrDefault(u => u.UserId == objFromDb.Id);
                if (userRole != null)
                {
                    var previousRoleName = db.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
                    //removing the old role
                    await userManager.RemoveFromRoleAsync(objFromDb, previousRoleName);

                }

                //add new role
                await userManager.AddToRoleAsync(objFromDb, db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
                objFromDb.Name = user.Name;
                db.SaveChanges();
                TempData[SD.Success] = "User has been edited successfully.";
                return RedirectToAction(nameof(Index));
            }


            user.RoleList = db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(user);
        }

        [HttpPost]
        public IActionResult LockUnlock(string userId)
        {
            var objFromDb = db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            if (objFromDb.LockoutEnd!=null && objFromDb.LockoutEnd > DateTime.Now)
            {
                //user is locked and will remain locked untill lockoutend time
                //clicking on this action will unlock them
                objFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked successfully.";
            }
            else
            {
                //user is not locked, and we want to lock the user
                objFromDb.LockoutEnd = new DateTime(4000, 1, 1);
                TempData[SD.Success] = "User locked successfully.";
            }
            db.SaveChanges();
            return RedirectToAction(nameof(Index));

        }
    }
}

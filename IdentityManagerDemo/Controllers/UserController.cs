using IdentityManagerDemo.Data;
using IdentityManagerDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

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

        [HttpPost]
        public IActionResult Delete(string userId)
        {
            var objFromDb = db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            db.ApplicationUser.Remove(objFromDb);
            db.SaveChanges();
            TempData[SD.Success] = "User deleted successfully.";
            return RedirectToAction(nameof(Index));
        }


        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            IdentityUser user = await userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            var existingUserClaims = await userManager.GetClaimsAsync(user);

            var model = new UserClaimsViewModel()
            {
                UserId = userId
            };

            foreach (Claim claim in ClaimStore.ClaimsList)
            {
                UserClaim userClaim = new UserClaim
                {
                    ClaimType = claim.Type
                };
                if (existingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.Claims.Add(userClaim);
            }

            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel userClaimsViewModel)
        {
            IdentityUser user = await userManager.FindByIdAsync(userClaimsViewModel.UserId);

            if (user == null)
            {
                return NotFound();
            }

            var claims = await userManager.GetClaimsAsync(user);
            var result = await userManager.RemoveClaimsAsync(user, claims);

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while removing claims";
                return View(userClaimsViewModel);
            }

            result = await userManager.AddClaimsAsync(user,
                userClaimsViewModel.Claims.Where(c => c.IsSelected).Select(c => new Claim(c.ClaimType, c.IsSelected.ToString()))
                );

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while adding claims";
                return View(userClaimsViewModel);
            }

            TempData[SD.Success] = "Claims updated successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}

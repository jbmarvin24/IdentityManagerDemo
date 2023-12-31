﻿using IdentityManagerDemo.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManagerDemo.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext db;
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public RoleController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.db=db;
            this.userManager=userManager;
            this.roleManager=roleManager;
        }
        public IActionResult Index()
        {
            var roles = db.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        public IActionResult Upsert(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                //update
                var objFromDb = db.Roles.FirstOrDefault(u => u.Id == id);
                return View(objFromDb);
            }
        }

        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if (await roleManager.RoleExistsAsync(roleObj.Name))
            {
                //error
                TempData[SD.Error] = "Role already exists.";
                return RedirectToAction(nameof(Index));
            } 
            if (string.IsNullOrEmpty(roleObj.Id))
            {
                //create
                await roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
                TempData[SD.Success] = "Role created successfully";
            }
            else
            {
                //update
                var objRoleFromDb = db.Roles.FirstOrDefault(u => u.Id == roleObj.Id);
                if (objRoleFromDb == null)
                {
                    TempData[SD.Error] = "Role not found.";
                    return RedirectToAction(nameof(Index));
                }
                objRoleFromDb.Name = roleObj.Name;
                objRoleFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await roleManager.UpdateAsync(objRoleFromDb);
                TempData[SD.Success] = "Role updated successfully";
            }
            return RedirectToAction(nameof(Index));

        }

        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var objFromDb = db.Roles.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null)
            {
                TempData[SD.Error] = "Role not found.";
                return RedirectToAction(nameof(Index));
            }
            var userRolesForThisRole = db.UserRoles.Where(u => u.RoleId == id).Count();
            if (userRolesForThisRole > 0)
            {
                TempData[SD.Error] = "Cannot delete this role, since there are users assigned to this role.";
                return RedirectToAction(nameof(Index));
            }
            await roleManager.DeleteAsync(objFromDb);
            TempData[SD.Success] = "Role deleted successfully.";
            return RedirectToAction(nameof(Index));

        }
    }
}

using IdentityManagerDemo.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityManagerDemo
{
    public class DataSeeder
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;

        public DataSeeder(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        public async Task SeedDataAsync()
        {
            await SeedRolesAsync();
            await SeedUsersAsync();
        }

        private async Task SeedRolesAsync()
        {
            if (!await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                var role = new IdentityRole("SuperAdmin");
                await _roleManager.CreateAsync(role);
            }

            if (!await _roleManager.RoleExistsAsync("Admin"))
            {
                var role = new IdentityRole("Admin");
                await _roleManager.CreateAsync(role);
            }

            if (!await _roleManager.RoleExistsAsync("User"))
            {
                var role = new IdentityRole("User");
                await _roleManager.CreateAsync(role);
            }
        }

        private async Task SeedUsersAsync()
        {
            if (await _userManager.FindByNameAsync("admin@example.com") == null)
            {
                var user = new ApplicationUser
                {
                    UserName = "admin@example.com",
                    Email = "admin@example.com",
                    Name = "Adminitrator",
                    EmailConfirmed = true
                };
                var result = await _userManager.CreateAsync(user, "P@ssw0rd");
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "SuperAdmin");
                }
            }
        }
    }
}

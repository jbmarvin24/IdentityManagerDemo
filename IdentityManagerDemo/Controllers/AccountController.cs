using IdentityManagerDemo.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManagerDemo.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register()
        {
            RegisterViewModel registerViewModel = new();
            return View(registerViewModel);
        }
    }
}

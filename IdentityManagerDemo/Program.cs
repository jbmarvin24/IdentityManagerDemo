using IdentityManagerDemo.Data;
using IdentityManagerDemo.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options => 
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(
    opt =>
    {
        opt.Password.RequiredLength = 5;
        opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
        opt.Lockout.MaxFailedAccessAttempts = 5;
    }
    ).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Home/AccessDenied");
});

builder.Services.AddAuthentication().AddFacebook(option =>
{
    option.AppId = "4049643451715865";
    option.AppSecret = "c2b8d1b7fe6b43ea23d0a5748cbaa53c";
});

builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

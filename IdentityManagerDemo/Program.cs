using IdentityManagerDemo;
using IdentityManagerDemo.Authorize;
using IdentityManagerDemo.Data;
using IdentityManagerDemo.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

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
        opt.SignIn.RequireConfirmedAccount = true;
    }
    ).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders().AddDefaultUI();

builder.Services.AddAuthentication()
    .AddFacebook(option =>
    {
        option.AppId = "4049643451715865";
        option.AppSecret = "c2b8d1b7fe6b43ea23d0a5748cbaa53c";
    }).AddGoogle(opt =>
    {
        opt.ClientId = "609536448061-2lagl136tkgcvrngfj0aotap6uadt09e.apps.googleusercontent.com";
        opt.ClientSecret = "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";
    }).AddMicrosoftAccount(opt =>
    {
        opt.ClientId = "8bd14544-c292-4a68-ad74-af9cb685bd74";
        opt.ClientSecret = "Hdz8Q~PTpNH3J-JWb-8pLUGuPaPjYOYrIPpNNcoC";
    });

builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();

builder.Services.AddRazorPages();

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    opt.AddPolicy("UserAndAdmin", policy => policy.RequireRole("Admin").RequireRole("User"));
    opt.AddPolicy("Admin_CreateAccess", policy => policy.RequireRole("Admin").RequireClaim("Create", "True"));
    opt.AddPolicy("Admin_Create_Edit_DeleteAccess", policy => policy.RequireRole("Admin").RequireClaim("Create", "True")
    .RequireClaim("Edit", "True")
    .RequireClaim("Delete", "True"));

    opt.AddPolicy("Admin_Create_Edit_DeleteAccess_OR_SuperAdmin", policy => policy.RequireAssertion(ctx => (
        ctx.User.IsInRole("Admin") && ctx.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
        && ctx.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
        && ctx.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    ) || ctx.User.IsInRole("SuperAdmin")));

    opt.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
});

builder.Services.AddTransient<DataSeeder>();

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


// Seeding data
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dataSeeder = services.GetRequiredService<DataSeeder>();
    await dataSeeder.SeedDataAsync();
}


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();

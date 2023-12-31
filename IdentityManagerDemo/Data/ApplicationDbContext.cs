﻿using IdentityManagerDemo.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityManagerDemo.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions options) :base(options)
        {
                
        }

        public DbSet<ApplicationUser> ApplicationUser { get; set; }
    }
}

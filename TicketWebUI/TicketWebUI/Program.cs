using InternProject.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NETCore.MailKit.Extensions;
using NETCore.MailKit.Infrastructure.Internal;
using TicketReviewApp.Models.Identity;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<InternProjectContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'dcstring' not found.")));
builder.Services.AddIdentity<AppUser, IdentityRole>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireUppercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Password.RequiredLength = 6;

    //

    opt.User.RequireUniqueEmail = true;
    opt.SignIn.RequireConfirmedEmail = true;
    opt.SignIn.RequireConfirmedPhoneNumber = false;

}).AddEntityFrameworkStores<InternProjectContext>().AddDefaultTokenProviders();
// Mail Sender Configs
builder.Services.AddMailKit(opt =>
{
    opt.UseMailKit(new MailKitOptions()
    {
        Server = "smtp.office365.com",
        Port = 587,
        SenderName = "Emrecan KAYNAR",
        SenderEmail = "emrecankaynar@hotmail.com",

        // can be optional with no authentication 
        Account = "emrecankaynar@hotmail.com",
        Password = "ds89c459ee",
        // enable ssl or tls
        Security = true

    });

});
// cookie configs
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.LoginPath = "/account/login";
    opt.LogoutPath = "/account/logout";
    opt.AccessDeniedPath = "/account/accesdenied";
    opt.SlidingExpiration = true;
    opt.ExpireTimeSpan = TimeSpan.FromMinutes(60);

    opt.Cookie = new CookieBuilder
    {
        HttpOnly = true,
        Name = ".TicketWebUI.Security.Cookie",
        SameSite = SameSiteMode.Strict,

    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
// configs


// configs //
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthentication();
app.UseRouting();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

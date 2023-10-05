using AutoMapper;

using InternProject.Models.Identity.IdentityDto;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using NETCore.MailKit.Core;
using System.Drawing.Printing;
using System.Net;
using System.Text;
using TicketReviewApp.Models.Identity;
using TicketReviewApp.Models.Identity.IdentityDto;

namespace TicketWebUI.Controllers
{
    public class AccountController : Controller
    {
        private IEmailService _mailservice;
        private IMapper _mapper;
        private UserManager<AppUser> _userManager;
        private SignInManager<AppUser> _signInManager;
        public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IMapper mapper, IEmailService mailservice)
        {
            _mailservice = mailservice;
            _mapper = mapper;
            _userManager = userManager;
            _signInManager = signInManager;
        }
        public async Task<IActionResult> ManageProfile(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
        
            if (user != null)
            {
                
                EditUserProfile userModel = _mapper.Map<EditUserProfile>(user);
                return View(userModel);

            }
            return View();
        }
        public async Task<IActionResult> Logout()
        {
            if (User.Identity.IsAuthenticated)
                await _signInManager.SignOutAsync();


            return RedirectToAction("Index", "Home");
        }
        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "Bu e-mail sistemde kayıtlı değil.");
                return View(model);
            }


            var confirmEmail = user.EmailConfirmed;
            if (confirmEmail != true)
            {
                ModelState.AddModelError("", "You have to confirm your mail adress first.");
                return View(model);
            }
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
            if (result.Succeeded)
            {
                SetCookie("userid", user.Id);
                ViewBag.Cookie = GetCookie("userid");
                return RedirectToAction("Index", "Home");
            }
            ModelState.AddModelError("", "Kullanıcı adı veya Şifre yanlış.");
            return View(model);
        }
        public IActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");
            return View(new RegisterModel());
        }
        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = _mapper.Map<AppUser>(model);

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                var url = Url.Action("ConfirmEmail", "Account", new {
                    userId = user.Id,
                    token = code
                });
                var sendingUrl = $"Lütfen email hesabınızı onaylamak için linke <a href='https://localhost:7278{url}'>tıklayınız.</a>";



                await _mailservice.SendAsync(user.Email, "E-mail Verification", sendingUrl, isHtml: true);

                TempData["warning"] = "Hesabınız oluşturuldu , e-mail adresinize gelen link ile hesabınızı onaylamalısınız";

                return RedirectToAction("Login", "Account");
            }

            ModelState.AddModelError("", "Beklenmeyen bir hata ile karşılaşıldı. Olası hatalar dizini => E-mail veya Username zaten kayıtlı.");
            return View(model);
        }
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    TempData["warning"] = "Mail adresi başarıyla onaylandı.";
                    return View();
                }
                TempData["warning"] = "Mail adresi bilinmeyen bir sebepten onaylanamadı!";
                return View();
            }
            TempData["warning"] = "Kullanıcı bulunamadı";
            return View();
        }
        public IActionResult PasswordReset()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> PasswordReset(ResetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                var userToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var url = Url.Action("ResetPasswordDetail", "Account", new
                {
                    userId = user.Id,
                    token = userToken,
                });
                var sendingUrl = $"Lütfen email hesabınızı onaylamak için linke <a href='https://localhost:7278{url}'>tıklayınız.</a>";
                await _mailservice.SendAsync(user.Email, "Reset Password", sendingUrl, isHtml: true);
                TempData["warning"] = "Mail adresinize sıfırlama linki gönderilmiştir.";
                return View();
            }
            TempData["warning"] = "Bu mail adresine ait bir kullanıcı bulunmamaktadır.";
            return View();

        }
        public async Task<IActionResult> ResetPasswordDetail(string userId, string token)
        {
            if (userId == null || token == null)
            {
                TempData["warning"] = "Kullanıcı ve token bilgisi eksik.";
                return RedirectToAction("Index", "Home");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                TempData["warning"] = "Bu kullanıcı mevcut değil.";
                return RedirectToAction("Index", "Home");
            }

            var model = new ResetPasswordDetailModel { Email = user.Email, Token = token };

            return View(model);

        }
        [HttpPost]
        public async Task<IActionResult> ResetPasswordDetail(ResetPasswordDetailModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }


            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                if (result.Succeeded)
                {
                    TempData["warning"] = "Şifre başarıyla değiştirildi";
                    return RedirectToAction("Login", "Account");
                }
                TempData["warning"] = "Bir hata meydana geldi [ResetPasswordDetail]";
                return RedirectToAction("Index", "Home");
            }
            TempData["warning"] = "Bişeyler ters Gitti [ResetPassowrdDetail]";
            return RedirectToAction("Index", "Home");
        }

        public void SetCookie(string key, string value)
        {
            HttpContext.Response.Cookies.Append(key, value);
        }
        public String GetCookie(string key)
        {
            HttpContext.Request.Cookies.TryGetValue(key, out string value);
            return value;
        }

        public IActionResult AccesDenied()
        {
            return View();
        }
    }
    }
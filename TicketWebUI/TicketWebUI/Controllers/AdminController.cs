using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NETCore.MailKit.Core;
using System.ComponentModel.Design;
using TicketReviewApp.Models.Identity;
using TicketReviewApp.Models.Identity.IdentityDto;

namespace TicketWebUI.Controllers
{
    [Authorize(Roles ="Admin")]
    public class AdminController : Controller
    {
        private RoleManager<IdentityRole> _roleManager;
        private IEmailService _mailservice;
        private IMapper _mapper;
        private UserManager<AppUser> _userManager;
        private SignInManager<AppUser> _signInManager;
        public AdminController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IMapper mapper, IEmailService mailservice, RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
            _mailservice = mailservice;
            _mapper = mapper;
            _userManager = userManager;
            _signInManager = signInManager;

        }
        [HttpPost]
        public async Task<IActionResult> UserEdit(UserEditModel model)
        {
           
            var allRoles = _roleManager.Roles.Select(i => i.Name).ToList();
            var user =  await  _userManager.FindByIdAsync(model.Id);
            if (user != null)
            {
                // farklı bir mapper methodu araştırılacak?
                user.SurName = model.SurName;
                user.Email= model.Email;
                user.EmailConfirmed = model.EmailConfirmed;
                user.PhoneNumber= model.PhoneNumber;
                user.Name= model.Name;
                user.UserName = model.UserName;
                // farklı bir mapper methodu araştırılacak?
                var updateResult = await _userManager.UpdateAsync(user);
                var userRecentRoles = await _userManager.GetRolesAsync(user);

                
                if (updateResult.Succeeded)
                {
                    if(userRecentRoles != null)
                    {
                        await _userManager.RemoveFromRolesAsync(user, userRecentRoles);
                    }
                    if(model.SelectedRoles != null) {
                        await _userManager.AddToRolesAsync(user, model.SelectedRoles);
                    }
                   

                    TempData["warning"] = "Kullanıcı başarıyla güncellendi.";
                    return RedirectToAction("UserList","Admin");
                }

            }
            TempData["warning"] = "Birşeyler ters gitti [HttpPost -> UserEdit]";
            return View();
        }



        [HttpGet]
        public async Task<IActionResult> UserEdit(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            
            if (user != null)
            {
                var selectedRoles = await _userManager.GetRolesAsync(user);
                var allRoles =  _roleManager.Roles.Select(i => i.Name).ToList();
                ViewBag.Roles = allRoles;
                var userEditModel = _mapper.Map<UserEditModel>(user);
                userEditModel.SelectedRoles = selectedRoles;
                return View(userEditModel);
            }
            TempData["warning"] = "ERROR => USER EDIT [HttpGet]";
            return RedirectToAction("UserList","Admin");
        }
        [HttpPost]
        public async Task<IActionResult> UserDelete(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if(user != null)
            {
                var result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    TempData["warning"] = "Kullanıcı Başarıyla Silindi";
                    return RedirectToAction("UserList");
                }
            }
            TempData["warning"] = "Bir hata oluştu ? => Kullanıcı bulunamadı";
            return RedirectToAction("UserList");
        }
        public async Task<IActionResult> UserList()
        { 
            var users = _userManager.Users.ToList();
            return View(users);
        }
        public IActionResult Index()
        {
            return View();
        }
        public IActionResult RoleList()
        {
            return View(_roleManager.Roles);
        }
        public IActionResult RoleCreate()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> RoleCreate(RoleModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _roleManager.CreateAsync(new IdentityRole { Name = model.Name });
            if (result.Succeeded)
            {
                return RedirectToAction("RoleList", "Admin");
            }
            else
            {
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError("", item.Description);
                }

            }
            TempData["warning"] = "Error [RoleCreate]";
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> RoleEdit(RoleEditModel model)
        {
           
            
                foreach (var userId in model.ItsToAdd ?? Array.Empty<string>())
                {
                    var user = await _userManager.FindByIdAsync(userId);
                    if (user != null)
                    {
                        var result = await _userManager.AddToRoleAsync(user, model.RoleName);
                     
                        if (!result.Succeeded)
                        {
                            foreach (var error in result.Errors)
                            {
                                ModelState.AddModelError("", error.Description);
                            }
                        }
                    }
                }

                foreach (var userId in model.ItsToDelete ??  Array.Empty<string>())
                {
                    var user = await _userManager.FindByIdAsync(userId);
                    if (user != null)
                    {
                        var result = await _userManager.RemoveFromRoleAsync(user, model.RoleName);
                        TempData["warning"] = "girdi f2";
                        if (!result.Succeeded)
                        {
                            foreach (var error in result.Errors)
                            {
                                ModelState.AddModelError("", error.Description);
                            }
                        }
                    }
                }
            
          
            return Redirect("/admin/roleedit/" + model.RoleId);
        }
        public async Task<IActionResult> RoleEdit(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);

            if (role != null)
            {
                var member = new List<AppUser>();
                var nonMember = new List<AppUser>();
                var users = _userManager.Users.ToList();
                foreach (var user in users)
                {
                    if (await _userManager.IsInRoleAsync(user,role.Name))
                    {
                        member.Add(user);
                    }
                    else
                    {
                        nonMember.Add(user);
                    }
                }
                var viewModel = new RoleDetailsModel() { nonMember = nonMember, member = member, Role = role };
                return View(viewModel);
            }
           
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> RoleDelete(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role != null)
            {
                var result = await _roleManager.DeleteAsync(role);
                if (result.Succeeded)
                {
                    return RedirectToAction("RoleList", "Admin");
                }
            }
            TempData["warning"] = "Rol Bulunamadı";
            return RedirectToAction("RoleList", "Admin");
        }
    }
}

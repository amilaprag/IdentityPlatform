using Data;
using Data.Models;
using IdentityPlatform.Data.Models;
using IdentityPlatform.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityPlatform.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly AppDbContext _appContext;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly IConfiguration _config;

        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, AppDbContext appContext, ILogger<AuthenticationController> logger, IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _appContext = appContext;
            _logger = logger;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register register)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Please provide required details");
            }
            var existuser = await _userManager.FindByEmailAsync(register.EmailAddress);
            if (existuser != null)
            {
                return BadRequest($"user {register.EmailAddress} already exists ");
            }

            ApplicationUser user = new ApplicationUser()
            {
                FirstName = register.FirstName,
                LastName = register.LastName,
                Email = register.EmailAddress,
                UserName = register.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(user, register.Password);
            if (result.Succeeded) return Ok("user created");

            return BadRequest($"User could not be created {result.Errors}");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Please provide required details");
            }
            var existuser = await _userManager.FindByEmailAsync(login.EmailAddress);
            if (existuser != null && await _userManager.CheckPasswordAsync(existuser, login.Password))
            {
                var token = await Token(existuser);
                return Ok(token);
            }

            return Unauthorized();
        }

        private async Task<IActionResult> Token([FromBody] ApplicationUser user)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var authSignningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_config["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _config["JWT:Issuer"],
                audience: _config["JWT:Audince"],
                expires: TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow.AddMinutes(5), TimeZoneInfo.FindSystemTimeZoneById("India Standard Time")),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSignningKey, SecurityAlgorithms.HmacSha256)
                );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JWTId = token.Id,
                UserId = user.Id,
                Isrevoke = false,
                DateAdded = DateTime.UtcNow,
                DateExpire = DateTime.Now.AddDays(1),
                SessionId = Guid.NewGuid().ToString()
            };

            await _appContext.RefreshToken.AddAsync(refreshToken);
            await _appContext.SaveChangesAsync();

            var result = new Session()
            {
                Token = jwtToken,
                Expireat = token.ValidTo,
                RefreshToken = refreshToken.SessionId
            };

            return Ok(result);
        }
    }
}
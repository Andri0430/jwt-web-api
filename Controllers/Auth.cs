using LearnJWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace LearnJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Auth : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public Auth(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet,Authorize]
        public ActionResult<object> GetMe()
        {
            var username = User.FindFirstValue(ClaimTypes.Name);
            var Role = User.FindFirstValue(ClaimTypes.Role);
            return Ok(new {username, Role});
        }

        [HttpPost("register")]
        public IActionResult Register(UserDto request)
        {
            if (request.UserName == user.Username)
            {
                return BadRequest("Akun Sudah Terdaftar!!!");
            }
            else
            {
                string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
                user.Username = request.UserName;
                user.PasswordHash = passwordHash;

                return Ok(user);
            }
        }

        [HttpPost("login")]
        public IActionResult Login(UserDto request)
        {
            if (request.UserName != user.Username)
            {
                return BadRequest("Akun Tidak Terdaftar!!!");
            }
            else
            {
                if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    return BadRequest("Password Salah!!!");
                }

                string token = CreateToken(user);

                var refreshToken = GetRefreshToken();
                SetRefreshToken(refreshToken);

                return Ok(token);
            }
        }

        [HttpPost("refresh-token")]
        public ActionResult<string> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token");
            }
            else if(user.TokenExpire < DateTime.Now)
            {
                return Unauthorized("Token Expired");
            }

            string token = CreateToken(user);
            var newRefreshToken = GetRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }

        private RefreshToken GetRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Create = DateTime.Now,
                Expires = DateTime.Now.AddDays(7)
            };
            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };

            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreate = newRefreshToken.Create;
            user.TokenExpire = newRefreshToken.Expires;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value
                ));

            var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddHours(1),
                    signingCredentials: creds
                );

            var sendToken = new JwtSecurityTokenHandler().WriteToken(token);
            return sendToken;
        }
    }
}
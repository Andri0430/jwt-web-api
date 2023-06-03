using LearnJWT.Dto;
using LearnJWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace LearnJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        [HttpPost("register")]
        public IActionResult Register([FromBody]UserDto request)
        {
            using (var hmac = new HMACSHA512())
            {
                user.PasswordHash  = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(request.Password));
                user.PasswordSalt = hmac.Key;
            }

            user.Username = request.Username;
            return Ok(user);
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody]UserDto request)
        {
            if(request.Username != user.Username)
            {
                return BadRequest("User Not Found!!!");
            }
            if (!VerifyPasswordHash(request.Password))
            {
                return BadRequest("Password Salah!!!");
            }

            return Ok("Berhasil Login");
        }

        private bool VerifyPasswordHash(string password)
        {
            using(var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text. Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(user.PasswordHash);
            }
        }
    }
}

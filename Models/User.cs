namespace LearnJWT.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime TokenCreate { get; set; }
        public DateTime TokenExpire { get; set; }
    }
}

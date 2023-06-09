namespace LearnJWT
{
    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime Create { get; set; }
        public DateTime Expires { get; set; }
    }
}

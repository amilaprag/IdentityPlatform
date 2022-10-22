namespace IdentityPlatform.Models
{
    public class Session
    {
        public string Token { get; set; }

        public DateTime Expireat { get; set; }

        public string RefreshToken { get; set; }
    }
}
using Authentication_and_Authorization_with_JWT.Models;

namespace Authentication_and_Authorization_with_JWT.Services.RefreshTokenService
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IUserService _userService;
        private readonly int RefreshTokenExpirationTime = 4;

        public RefreshTokenService(IHttpContextAccessor httpContextAccessor, IUserService userService)
        {
            _httpContextAccessor = httpContextAccessor;
            _userService = userService;
        }

        public RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = GenerateRandomToken(),
                Created = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(RefreshTokenExpirationTime)
            };

            return refreshToken;
        }

        private string GenerateRandomToken()
        {
            byte[] randomNumber = new byte[64];

            using (var randomNumberGenerator = RandomNumberGenerator.Create()) 
            {
                randomNumberGenerator.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public void SetRefreshTokenCookie(int userId, RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires,
                Secure = true, // Set to true if your application is served over HTTPS
                SameSite = SameSiteMode.Strict
            };

            _httpContextAccessor.HttpContext.Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            _userService.UpdateUserRefreshToken(userId, newRefreshToken.Token, newRefreshToken.Created, newRefreshToken.Expires);
        }
    }
}

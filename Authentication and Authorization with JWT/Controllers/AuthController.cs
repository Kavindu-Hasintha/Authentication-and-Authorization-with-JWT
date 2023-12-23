using Authentication_and_Authorization_with_JWT.Services.JwtTokenService;
using Authentication_and_Authorization_with_JWT.Services.RefreshTokenService;

namespace Authentication_and_Authorization_with_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _config;
        private readonly IUserService _userService;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IRefreshTokenService _refreshTokenService;
        public AuthController(IConfiguration config, IUserService userService, IRefreshTokenService refreshTokenService, IJwtTokenService jwtTokenService) 
        {
            _config = config;
            _userService = userService;
            _jwtTokenService = jwtTokenService;
            _refreshTokenService = refreshTokenService;
        }

        [HttpGet]
        [Route("getclaims")]
        [Authorize]
        public ActionResult<string> GetMe()
        {
            var username = _userService.GetMyName();
            return Ok(username);
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegisterRequest request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.UserRole = request.UserRole;

            return Ok(user);
        }

        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<string>> Login(UserLoginRequest request)
        {
            /*
            var user = await _userService.GetUserByUsernameAsync(request.Username);

            if (user == null)
            {
                return BadRequest("User not found.");
            }
            */
            if (request.Username != user.Username)
            {
                return BadRequest("User not found.");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Incorrect password.");
            }

            string token = _jwtTokenService.CreateToken(user);

            var refreshToken = _refreshTokenService.GenerateRefreshToken();
            SetRefreshTokenCookie(refreshToken);

            return Ok(new { Token = token, RefreshToken = refreshToken.Token });
        }

        [HttpPost]
        [Route("refreshtoken")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token");
            }
            else if (user.TokenExpired < DateTime.UtcNow)
            {
                return Unauthorized("Token expired");
            }

            string token = _jwtTokenService.CreateToken(user);
            // var newRefreshToken = GenerateRefreshToken();
            // SetRefreshToken(newRefreshToken);

            return Ok(token);
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private void SetRefreshTokenCookie(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires,
                Secure = true, // Set to true if your application is served over HTTPS
                SameSite = SameSiteMode.Strict
            };

            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpired = newRefreshToken.Expires;
        }
    }
}

namespace Authentication_and_Authorization_with_JWT.Services.RefreshTokenService
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly int RefreshTokenExpirationTime = 4;
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
    }
}

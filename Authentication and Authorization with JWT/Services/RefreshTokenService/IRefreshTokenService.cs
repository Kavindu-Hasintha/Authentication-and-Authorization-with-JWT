namespace Authentication_and_Authorization_with_JWT.Services.RefreshTokenService
{
    public interface IRefreshTokenService
    {
        RefreshToken GenerateRefreshToken();
        void SetRefreshTokenCookie(int userId, RefreshToken newRefreshToken);
    }
}

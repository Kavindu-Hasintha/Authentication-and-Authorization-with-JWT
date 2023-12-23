namespace Authentication_and_Authorization_with_JWT.Services.JwtTokenService
{
    public interface IJwtTokenService
    {
        string CreateToken(User user);
    }
}

using Authentication_and_Authorization_with_JWT.Models;

namespace Authentication_and_Authorization_with_JWT.Services.UserService
{
    public interface IUserService
    {
        string GetMyName();
        Task<User> GetUserByUsernameAsync(string username);
        Task<bool> UpdateUserRefreshToken(int userId, string refreshToken, DateTime created, DateTime expires);
    }
}

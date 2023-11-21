namespace Authentication_and_Authorization_with_JWT.Models
{
    public class UserRegisterRequest
    {
        [Required]
        public string Username { get; set; } = string.Empty;
        [Required, MinLength(6, ErrorMessage = "Password length mush be between 6 and 24 included."), MaxLength(24, ErrorMessage = "Password length mush be between 6 and 24 included.")]
        public string Password { get; set; } = string.Empty;
        [Required]
        public Role UserRole { get; set; }
    }
}

﻿namespace Authentication_and_Authorization_with_JWT.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public Role UserRole { get; set; }
    }
}

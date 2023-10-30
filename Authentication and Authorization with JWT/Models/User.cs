namespace Authentication_and_Authorization_with_JWT.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }

        // Hashing is a one-way process that converts a password to ciphertext using hash algorithms.
        // A hashed password cannot be decrypted, but a hacker can try to reverse engineer it.
        // Password salting adds random characters before or after a password prior to hashing to
        // obfuscate the actual password.
        // This way even hash is reversed by a hacker, he/she gets salt password not the actual one.
    }
}

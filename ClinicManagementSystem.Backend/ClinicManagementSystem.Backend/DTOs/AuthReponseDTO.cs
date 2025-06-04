namespace ClinicManagementSystem.Backend.DTOs
{
    public class AuthReponseDTO
    {
        public string Status { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
    }
}

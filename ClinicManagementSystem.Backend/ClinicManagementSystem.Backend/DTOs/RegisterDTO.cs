using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace ClinicManagementSystem.Backend.DTOs
{
    public class RegisterDTO
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}

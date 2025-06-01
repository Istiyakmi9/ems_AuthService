namespace ems_AuthServiceLayer.Models
{
    public class SignInRequestModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string Mobile { get; set; }
        public string CompanyCode { get; set; }
        public long UserId { set; get; }
        public string ComfirmPassword { get; set; }
    }
}

using Bot.CoreBottomHalf.CommonModal;
using ems_AuthServiceLayer.Models;

namespace ems_AuthServiceLayer.Contracts
{
    public interface ILoginService
    {
        Task<string> EncryptDetailService(string text);
        Task<string> DecryptDetailService(string text);
        Task<Tuple<string, string>> GenerateNewRegistrationPassword();
        Task<AuthResponse> AuthenticateUser(SignInRequestModel signInRequest);
        Task<AuthResponse> FetchAuthenticatedProviderDetail(UserDetail authUser);
        Task<bool> RegisterNewCompany(RegistrationForm registrationForm);
        Boolean RemoveUserDetailService(string Token);
        UserDetail GetUserDetail(AuthUser authUser);
        string ResetEmployeePassword(UserDetail authUser);
        Task<string> ForgotPasswordService(string email);
        Task<string> ReGenerateTokenService();
    }
}

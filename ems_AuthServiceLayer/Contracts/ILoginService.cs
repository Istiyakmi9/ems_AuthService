using Bot.CoreBottomHalf.CommonModal;

namespace ems_AuthServiceLayer.Contracts
{
    public interface ILoginService
    {
        Task<Tuple<string, string>> GenerateNewRegistrationPassword();
        Task<LoginResponse> AuthenticateUser(UserDetail authUser);
        Task<LoginResponse> FetchAuthenticatedProviderDetail(UserDetail authUser);
        Task<bool> RegisterNewCompany(RegistrationForm registrationForm);
        Boolean RemoveUserDetailService(string Token);
        UserDetail GetUserDetail(AuthUser authUser);
        string ResetEmployeePassword(UserDetail authUser);
        Task<string> ForgotPasswordService(string email);
    }
}

using Bot.CoreBottomHalf.CommonModal;

namespace ems_AuthServiceLayer.Contracts
{
    public interface IAuthenticationService
    {
        Task<RefreshTokenModal> Authenticate(UserDetail userDetail);
        string ReadJwtToken();
    }
}

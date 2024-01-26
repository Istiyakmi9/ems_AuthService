using Bot.CoreBottomHalf.CommonModal;

namespace ems_AuthServiceLayer.Contracts
{
    public interface IAuthenticationService
    {
        public RefreshTokenModal Authenticate(UserDetail userDetail);
        string ReadJwtToken();
    }
}

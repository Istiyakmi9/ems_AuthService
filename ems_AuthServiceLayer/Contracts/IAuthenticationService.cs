
using Bt.Ems.Lib.User.Db.Model;

namespace ems_AuthServiceLayer.Contracts
{
    public interface IAuthenticationService
    {
        Task<Bot.CoreBottomHalf.CommonModal.RefreshTokenModal> Authenticate(CurrentSession session);
        string ReadJwtToken();
    }
}

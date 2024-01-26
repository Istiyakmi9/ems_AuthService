namespace ems_AuthServiceLayer.Models
{
    public class Procedures
    {
        public static string UserDetail_GetByMobileOrEmail = "sp_UserDetail_GetByMobileOrEmail";

        public static string New_Registration = "sp_new_registration";
        public static string UpdateRefreshToken = "sp_UpdateRefreshToken";
        public static string AuthenticationToken_VerifyAndGet = "SP_AuthenticationToken_VerifyAndGet";
    }
}

using Bot.CoreBottomHalf.CommonModal;
using Bot.CoreBottomHalf.CommonModal.API;
using ems_AuthServiceLayer.Contracts;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace ems_AuthService.Controller
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : BaseController
    {
        private readonly ILoginService loginService;

        public LoginController(ILoginService loginService)
        {
            this.loginService = loginService;
        }

        [HttpGet]
        [Route("LogoutUser")]
        public IResponse<ApiResponse> LogoutUser(string Token)
        {
            bool ResultFlag = this.loginService.RemoveUserDetailService(Token);
            return BuildResponse(ResultFlag, HttpStatusCode.OK);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("SignUpNew")]
        public async Task<ApiResponse> SignUpNew(RegistrationForm registrationForm)
        {
            var userDetail = await this.loginService.RegisterNewCompany(registrationForm);
            return BuildResponse(userDetail, HttpStatusCode.OK);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("AuthenticateProvider")]
        public async Task<ApiResponse> AuthenticateProvider(UserDetail authUser)
        {
            var userDetail = await this.loginService.FetchAuthenticatedProviderDetail(authUser);
            return BuildResponse(userDetail, HttpStatusCode.OK);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("Authenticate")]
        public async Task<ApiResponse> Authenticate(UserDetail authUser)
        {
            var userDetail = await this.loginService.AuthenticateUser(authUser);
            return BuildResponse(userDetail, HttpStatusCode.OK);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("GenerateTempraryPassword")]
        public async Task<ApiResponse> GenerateTempraryPassword()
        {
            var userDetail = await this.loginService.GenerateRandomPassword(10);
            return BuildResponse(userDetail, HttpStatusCode.OK);
        }

        [HttpPost]
        [Route("GetUserDetail")]
        public IResponse<ApiResponse> GetUserDetail(AuthUser authUser)
        {
            var userDetail = this.loginService.GetUserDetail(authUser);
            return BuildResponse(userDetail, HttpStatusCode.OK);
        }

        [HttpPost("ResetEmployeePassword")]
        public IResponse<ApiResponse> ResetEmployeePassword(UserDetail authUser)
        {
            var result = this.loginService.ResetEmployeePassword(authUser);
            return BuildResponse(result, HttpStatusCode.OK);
        }

        [HttpPost("ForgotPassword")]
        [AllowAnonymous]
        public async Task<ApiResponse> ForgotPassword([FromBody] UserDetail user)
        {
            var result = await this.loginService.ForgotPasswordService(user.EmailId);
            return BuildResponse(result, HttpStatusCode.OK);
        }
    }
}

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

        [HttpGet]
        [AllowAnonymous]
        [Route("GenerateTempraryPassword")]
        public async Task<ApiResponse> GenerateTempraryPassword()
        {
            var userDetail = await this.loginService.GenerateNewRegistrationPassword();
            return BuildResponse(userDetail.Item1, HttpStatusCode.OK, string.Empty, userDetail.Item2);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("DecryptDetail/{text}")]
        public async Task<ApiResponse> DecryptDetail(string text)
        {
            var result = await this.loginService.DecryptDetailService(text);
            return BuildResponse(result, HttpStatusCode.OK);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("EncryptDetail/{text}")]
        public async Task<ApiResponse> EncryptDetail(string text)
        {
            var result = await this.loginService.EncryptDetailService(text);
            return BuildResponse(result, HttpStatusCode.OK);
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

        [AllowAnonymous]
        [HttpGet("GenerateToken/{companyCode}")]
        public async Task<ApiResponse> GenerateToken([FromRoute] string companyCode)
        {
            var userDetail = await loginService.GenerateTokenService(companyCode);
            return BuildResponse(userDetail, HttpStatusCode.OK);
        }
    }
}

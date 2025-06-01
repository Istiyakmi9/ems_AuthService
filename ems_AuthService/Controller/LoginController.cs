using Bot.CoreBottomHalf.CommonModal;
using Bt.Ems.Lib.User.Db.Model.MicroserviceModel;
using ems_AuthServiceLayer.Contracts;
using ems_AuthServiceLayer.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using UserDetail = Bt.Ems.Lib.User.Db.Model.UserDetail;

namespace ems_AuthService.Controller
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/auth/[controller]")]
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
        public async Task<ApiResponse> LogoutUser(string Token)
        {
            bool ResultFlag = this.loginService.RemoveUserDetailService(Token);
            return await BuildResponseAsync(ResultFlag, HttpStatusCode.OK);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("SignUpNew")]
        public async Task<ApiResponse> SignUpNew(RegistrationForm registrationForm)
        {
            var userDetail = await this.loginService.RegisterNewCompany(registrationForm);
            return await BuildResponseAsync(userDetail, HttpStatusCode.OK);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("AuthenticateProvider")]
        public async Task<ApiResponse> AuthenticateProvider(UserDetail authUser)
        {
            var userDetail = await this.loginService.FetchAuthenticatedProviderDetail(authUser);
            return await BuildResponseAsync(userDetail, HttpStatusCode.OK);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("Authenticate")]
        public async Task<ApiResponse> Authenticate(SignInRequestModel signInRequest)
        {
            try
            {
                var userDetail = await this.loginService.AuthenticateUser(signInRequest);
                return await BuildResponseAsync(userDetail, HttpStatusCode.OK);
            }
            catch (Exception ex)
            {
                throw Throw(ex, signInRequest);
            }
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("GenerateTempraryPassword")]
        public async Task<ApiResponse> GenerateTempraryPassword()
        {
            var userDetail = await this.loginService.GenerateNewRegistrationPassword();
            return await BuildResponseAsync(userDetail.Item1, HttpStatusCode.OK, string.Empty, userDetail.Item2);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("DecryptDetail/{text}")]
        public async Task<ApiResponse> DecryptDetail(string text)
        {
            var result = await this.loginService.DecryptDetailService(text);
            return await BuildResponseAsync(result, HttpStatusCode.OK);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("EncryptDetail/{text}")]
        public async Task<ApiResponse> EncryptDetail(string text)
        {
            var result = await this.loginService.EncryptDetailService(text);
            return await BuildResponseAsync(result, HttpStatusCode.OK);
        }

        [HttpPost]
        [Route("GetUserDetail")]
        public async Task<ApiResponse> GetUserDetail(AuthUser authUser)
        {
            var userDetail = this.loginService.GetUserDetail(authUser);
            return await BuildResponseAsync(userDetail, HttpStatusCode.OK);
        }

        [HttpPost("ResetEmployeePassword")]
        public async Task<ApiResponse> ResetEmployeePassword(UserDetail authUser)
        {
            try
            {
                var result = this.loginService.ResetEmployeePassword(authUser);
                return await BuildResponseAsync(result, HttpStatusCode.OK);
            }
            catch (Exception ex)
            {
                throw Throw(ex, authUser);
            }
        }

        [HttpPost("ForgotPassword")]
        [AllowAnonymous]
        public async Task<ApiResponse> ForgotPassword([FromBody] UserDetail user)
        {
            try
            {
                var result = await this.loginService.ForgotPasswordService(user.EmailId);
                return await BuildResponseAsync(result, HttpStatusCode.OK);
            }
            catch (Exception ex)
            {
                throw Throw(ex, user);
            }
        }

        [HttpGet("ReGenerateToken")]
        public async Task<ApiResponse> GenerateToken()
        {
            var token = await loginService.ReGenerateTokenService();
            return await BuildResponseAsync(token, HttpStatusCode.OK);
        }
    }
}

using Bot.CoreBottomHalf.CommonModal;
using Bt.Ems.Lib.PipelineConfig.MicroserviceHttpRequest;
using Bt.Ems.Lib.PipelineConfig.Model;
using Bt.Ems.Lib.PipelineConfig.Model.Constants;
using Bt.Ems.Lib.PipelineConfig.Model.ExceptionModel;
using Bt.Ems.Lib.User.Db.Common;
using Bt.Ems.Lib.User.Db.Model;
using ems_AuthServiceLayer.Contracts;
using ems_AuthServiceLayer.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using ModalLayer.Modal;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserDetail = Bt.Ems.Lib.User.Db.Model.UserDetail;

namespace ems_AuthServiceLayer.Service
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IDb _db;
        private readonly CurrentSession _currentSession;
        private readonly PublicKeyDetail _publicKeyDetail;
        private readonly RequestMicroservice _requestMicroservice;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IWebHostEnvironment _env;

        public AuthenticationService(IDb db,
            CurrentSession currentSession,
            PublicKeyDetail publicKeyDetail,
            RequestMicroservice requestMicroservice,
            IHttpClientFactory httpClientFactory,
            IWebHostEnvironment env)
        {
            _db = db;
            _currentSession = currentSession;
            _publicKeyDetail = publicKeyDetail;
            _requestMicroservice = requestMicroservice;
            _httpClientFactory = httpClientFactory;
            _env = env;
        }

        struct UserClaims
        {

        }

        public string ReadJwtToken()
        {
            string userId = string.Empty;
            if (!string.IsNullOrEmpty(_currentSession.Authorization))
            {
                string token = _currentSession.Authorization.Replace("Bearer", "").Trim();
                if (!string.IsNullOrEmpty(token) && token != "null")
                {
                    var handler = new JwtSecurityTokenHandler();
                    handler.ValidateToken(token, new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = false,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = _publicKeyDetail.Issuer, //_configuration["jwtSetting:Issuer"],
                        ValidAudience = _publicKeyDetail.Issuer, //_configuration["jwtSetting:Issuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_publicKeyDetail.Key))
                    }, out SecurityToken validatedToken);

                    var securityToken = handler.ReadToken(token) as JwtSecurityToken;
                    userId = securityToken.Claims.FirstOrDefault(x => x.Type == "unique_name").Value;
                }
            }
            return userId;
        }

        public async Task<RefreshTokenModal> Authenticate(CurrentSession session)
        {
            string role = string.Empty;
            switch (session.RoleId)
            {
                case 1:
                    role = Role.Admin;
                    break;
                case 2:
                    role = Role.Employee;
                    break;
                case 3:
                    role = Role.Manager;
                    break;
            }

            var claims = new Dictionary<string, string>
            {
                { ApplicationConstants.CurrentSession, JsonConvert.SerializeObject(session) },
                { ApplicationConstants.CompanyCode, session.CompanyCode },
                { ClaimTypes.Role, role },
            };

            string generatedToken = await GenerateJwtTokenService(claims);
            var refreshToken = GenerateRefreshToken(null);
            refreshToken.Token = generatedToken;
            return refreshToken;
        }

        private async Task<string> GenerateJwtTokenService(Dictionary<string, string> claims)
        {
            string url = string.Empty;
            //if (_env.IsProduction())
            //{
            //    url = $"https://www.bottomhalf.in/bt/s3/TokenManager/generateToken";
            //}
            //else
            //{
            //    url = $"http://localhost:5052/bt/s3/TokenManager/generateToken";
            //}
            url = $"https://www.bottomhalf.in/bt/s3/TokenManager/generateToken";

            var client = _httpClientFactory.CreateClient();
            var content = new StringContent(JsonConvert.SerializeObject(claims), Encoding.UTF8, "application/json");

            var response = await client.PostAsync(url, content);
            if (!response.IsSuccessStatusCode)
                throw EmstumException.ThrowBadRequest($"Request failed with status code {response.StatusCode}");

            return await response.Content.ReadAsStringAsync();
        }

        private string GenerateAccessToken(UserDetail userDetail, string role)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var num = new Random().Next(1, 10);
            //userDetail.EmployeeId += num + 7;
            //userDetail.ReportingManagerId += num + 7;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Sid, userDetail.UserId.ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, userDetail.EmailId),
                    new Claim(ClaimTypes.Role, role),
                    new Claim(JwtRegisteredClaimNames.Aud, num.ToString()),
                    new Claim(ClaimTypes.Version, "1.0.0"),
                    new Claim(ApplicationConstants.CompanyCode, userDetail.CompanyCode),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ApplicationConstants.JBot, JsonConvert.SerializeObject(userDetail))
                }),

                //----------- Expiry time at after what time token will get expired -----------------------------
                Expires = DateTime.UtcNow.AddSeconds(_publicKeyDetail.DefaulExpiryTimeInSeconds * 12),

                SigningCredentials = new SigningCredentials(
                                            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_publicKeyDetail.Key)),
                                            SecurityAlgorithms.HmacSha256
                                     )
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var generatedToken = tokenHandler.WriteToken(token);
            return generatedToken;
        }

        private void SaveRefreshToken(RefreshTokenModal refreshToken, long userId)
        {
            _db.Execute<string>(Procedures.UpdateRefreshToken, new
            {
                UserId = userId,
                RefreshToken = refreshToken.RefreshToken,
                ExpiryTime = refreshToken.Expires
            }, false);
        }

        public RefreshTokenModal GenerateRefreshToken(string ipAddress)
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshTokenModal
                {
                    RefreshToken = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddSeconds(_publicKeyDetail.DefaultRefreshTokenExpiryTimeInSeconds),
                    Created = DateTime.UtcNow,
                    CreatedByIp = ipAddress
                };
            }
        }
    }
}

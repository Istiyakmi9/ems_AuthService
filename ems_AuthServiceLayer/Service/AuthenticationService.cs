﻿using Bot.CoreBottomHalf.CommonModal;
using BottomhalfCore.DatabaseLayer.Common.Code;
using ems_AuthServiceLayer.Contracts;
using ems_AuthServiceLayer.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ems_AuthServiceLayer.Service
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly JwtSetting _jwtSetting;
        private readonly IDb _db;
        private readonly CurrentSession _currentSession;
        public AuthenticationService(IOptions<JwtSetting> options, IDb db, CurrentSession currentSession)
        {
            _jwtSetting = options.Value;
            _db = db;
            _currentSession = currentSession;
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
                        ValidIssuer = _jwtSetting.Issuer, //_configuration["jwtSetting:Issuer"],
                        ValidAudience = _jwtSetting.Issuer, //_configuration["jwtSetting:Issuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSetting.Key))
                    }, out SecurityToken validatedToken);

                    var securityToken = handler.ReadToken(token) as JwtSecurityToken;
                    userId = securityToken.Claims.FirstOrDefault(x => x.Type == "unique_name").Value;
                }
            }
            return userId;
        }

        public RefreshTokenModal Authenticate(UserDetail userDetail)
        {
            string role = string.Empty;
            switch (userDetail.RoleId)
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

            string generatedToken = GenerateAccessToken(userDetail, role);
            var refreshToken = GenerateRefreshToken(null);
            refreshToken.Token = generatedToken;
            // SaveRefreshToken(refreshToken, userDetail.UserId);
            return refreshToken;
        }

        private string GenerateAccessToken(UserDetail userDetail, string role)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var num = new Random().Next(1, 10);
            //userDetail.EmployeeId += num + 7;
            //userDetail.ReportingManagerId += num + 7;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new Claim[] {
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
                Expires = DateTime.UtcNow.AddSeconds(_jwtSetting.AccessTokenExpiryTimeInSeconds * 12),

                SigningCredentials = new SigningCredentials(
                                            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSetting.Key)),
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
                    Expires = DateTime.UtcNow.AddSeconds(_jwtSetting.RefreshTokenExpiryTimeInSeconds),
                    Created = DateTime.UtcNow,
                    CreatedByIp = ipAddress
                };
            }
        }
    }
}

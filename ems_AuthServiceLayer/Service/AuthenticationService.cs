using Bot.CoreBottomHalf.CommonModal;
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
            SaveRefreshToken(refreshToken, userDetail.UserId);
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

        public async Task<RefreshTokenModal> RenewAndGenerateNewToken(string Mobile, string Email, string UserRole)
        {
            //long UserId = 0;
            //string TokenUserId = ReadJwtToken();
            //if (!string.IsNullOrEmpty(TokenUserId))
            //    UserId = Convert.ToInt64(TokenUserId);
            //RefreshTokenModal refreshTokenModal = default;
            //if (UserId > 0 || !string.IsNullOrEmpty(Email) || !string.IsNullOrEmpty(Mobile))
            //{
            //    var ResultSet = await _db.GetDataSetAsync(Procedures.AuthenticationToken_VerifyAndGet, new
            //    {
            //        UserId,
            //        Mobile,
            //        Email,
            //    });

            //    if (ResultSet.Tables.Count > 0)
            //    {
            //        var Result = Converter.ToList<TokenModal>(ResultSet.Tables[0]);
            //        if (Result.Count > 0)
            //        {
            //            var currentModal = Result.FirstOrDefault();
            //            refreshTokenModal = new RefreshTokenModal
            //            {
            //                Token = null, // GenerateAccessToken(UserId.ToString(), "0", UserRole),
            //                Expires = currentModal.ExpiryTime
            //            };
            //        }
            //    }
            //}
            var refreshTokenModal = new RefreshTokenModal();
            return refreshTokenModal;
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

        private int GetSaltSize(byte[] passwordBytes)
        {
            var key = new Rfc2898DeriveBytes(passwordBytes, passwordBytes, 1000);
            byte[] ba = key.GetBytes(2);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < ba.Length; i++)
            {
                sb.Append(Convert.ToInt32(ba[i]).ToString());
            }
            int saltSize = 0;
            string s = sb.ToString();
            foreach (char c in s)
            {
                int intc = Convert.ToInt32(c.ToString());
                saltSize = saltSize + intc;
            }

            return saltSize;
        }
        public byte[] GetRandomBytes(int length)
        {
            byte[] ba = new byte[length];
            RNGCryptoServiceProvider.Create().GetBytes(ba);
            return ba;
        }

        public string Encrypt(string textOrPassword, string secretKey)
        {
            byte[] originalBytes = Encoding.UTF8.GetBytes(textOrPassword);
            byte[] encryptedBytes = null;
            byte[] passwordBytes = Encoding.UTF8.GetBytes(secretKey);

            // Hash the password with SHA256  
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            // Getting the salt size  
            int saltSize = GetSaltSize(passwordBytes);
            // Generating salt bytes  
            byte[] saltBytes = GetRandomBytes(saltSize);

            // Appending salt bytes to original bytes  
            byte[] bytesToBeEncrypted = new byte[saltBytes.Length + originalBytes.Length];
            for (int i = 0; i < saltBytes.Length; i++)
            {
                bytesToBeEncrypted[i] = saltBytes[i];
            }
            for (int i = 0; i < originalBytes.Length; i++)
            {
                bytesToBeEncrypted[i + saltBytes.Length] = originalBytes[i];
            }

            encryptedBytes = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

            return Convert.ToBase64String(encryptedBytes);
        }

        public string Decrypt(string encryptedText, string secretKey)
        {
            byte[] bytesToBeDecrypted = Convert.FromBase64String(encryptedText);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(secretKey);

            // Hash the password with SHA256  
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] decryptedBytes = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

            if (decryptedBytes != null)
            {
                // Getting the size of salt  
                int saltSize = GetSaltSize(passwordBytes);

                // Removing salt bytes, retrieving original bytes  
                byte[] originalBytes = new byte[decryptedBytes.Length - saltSize];
                for (int i = saltSize; i < decryptedBytes.Length; i++)
                {
                    originalBytes[i - saltSize] = decryptedBytes[i];
                }
                return Encoding.UTF8.GetString(originalBytes);
            }
            else
            {
                return null;
            }
        }

        private byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:  
            byte[] saltBytes = passwordBytes;
            // Example:  
            //saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };  

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (CryptoStream cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }
        private byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            try
            {
                byte[] decryptedBytes = null;
                // Set your salt here to meet your flavor:  
                byte[] saltBytes = passwordBytes;
                // Example:  
                //saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };  

                using (MemoryStream ms = new MemoryStream())
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        //AES.Mode = CipherMode.CBC;  

                        using (CryptoStream cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            //If(cs.Length = ""  
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                }
                return decryptedBytes;
            }
            catch (Exception Ex)
            {
                throw Ex;
            }
        }
    }
}

using Bot.CoreBottomHalf.CommonModal;
using BottomHalf.Utilities.UtilService;
using BottomhalfCore.Services.Code;
using Bt.Ems.Lib.CommonShared.EmployeeEnums;
using Bt.Ems.Lib.CommonShared.FilesModel;
using Bt.Ems.Lib.PipelineConfig.KafkaService.interfaces;
using Bt.Ems.Lib.PipelineConfig.Model;
using Bt.Ems.Lib.PipelineConfig.Model.Constants;
using Bt.Ems.Lib.PipelineConfig.Model.KafkaModel;
using Bt.Ems.Lib.User.Db.Common;
using Bt.Ems.Lib.User.Db.Model;
using ems_AuthServiceLayer.Contracts;
using ems_AuthServiceLayer.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using ModalLayer.Modal;
using Newtonsoft.Json;
using System.Data;
using System.Net.Mail;
using LoginDetail = Bt.Ems.Lib.User.Db.Model.LoginDetail;
using UserDetail = Bt.Ems.Lib.User.Db.Model.UserDetail;

namespace ems_AuthServiceLayer.Service
{
    public class LoginService : ILoginService
    {
        private readonly IDb db;
        private readonly JwtSetting _jwtSetting;
        private readonly IAuthenticationService _authenticationService;
        private readonly IConfiguration _configuration;
        private readonly CurrentSession _currentSession;
        private readonly IKafkaProducerService _kafkaProducerService;
        private readonly PublicKeyDetail _publicKeyDetail;

        public LoginService(IDb db, IOptions<JwtSetting> options,
            IAuthenticationService authenticationService,
            IConfiguration configuration,
            CurrentSession currentSession, IKafkaProducerService kafkaProducerService, PublicKeyDetail publicKeyDetail)
        {
            this.db = db;
            _configuration = configuration;
            _jwtSetting = options.Value;
            _authenticationService = authenticationService;
            _currentSession = currentSession;
            _kafkaProducerService = kafkaProducerService;
            _publicKeyDetail = publicKeyDetail;
        }

        public Boolean RemoveUserDetailService(string Token)
        {
            Boolean Flag = false;
            return Flag;
        }
        public UserDetail GetUserDetail(AuthUser authUser)
        {
            UserDetail userDetail = this.db.Get<UserDetail>(Procedures.UserDetail_GetByMobileOrEmail, new
            {
                email = authUser.Email,
                mobile = authUser.MobileNo,
            });

            return userDetail;
        }

        public UserDetail GetUserLoginDetail(SignInRequestModel signInRequest)
        {
            if (!string.IsNullOrEmpty(signInRequest.Email))
                signInRequest.Email = signInRequest.Email.Trim().ToLower();

            var userDetail = db.Get<UserDetail>("sp_password_get_by_email_mobile", new
            {
                signInRequest.UserId,
                MobileNo = signInRequest.Mobile,
                EmailId = signInRequest.Email
            });

            if (userDetail == null)
                throw HiringBellException.ThrowBadRequest("Please enter a valid email address or mobile number.");

            ValidePasswordStatus(userDetail);

            return userDetail;
        }

        private void ValidePasswordStatus(LoginDetail loginDetail)
        {
            if (loginDetail.UserTypeId == 101)
            {
                var applicationSettings = db.Get<ApplicationSettings>("sp_application_setting_get_by_compid", new
                {
                    loginDetail.CompanyId,
                    SettingsCatagoryId = 2
                });

                if (applicationSettings == null || string.IsNullOrEmpty(applicationSettings.SettingDetails))
                    throw HiringBellException.ThrowBadRequest("Your password got expired. Please contact to admin.");

                var passwordSettings = JsonConvert.DeserializeObject<PasswordSettings>(applicationSettings.SettingDetails);

                if (DateTime.UtcNow.Subtract(loginDetail.UpdatedOn).TotalSeconds > passwordSettings.TemporaryPasswordExpiryTimeInSeconds)
                    throw HiringBellException.ThrowBadRequest("Your temporary password got expired. Please reset again.");
            }
        }

        public string FetchUserLoginDetail(UserDetail authUser)
        {
            string encryptedPassword = string.Empty;

            if (!string.IsNullOrEmpty(authUser.EmailId))
                authUser.EmailId = authUser.EmailId.Trim().ToLower();

            var loginDetail = db.Get<UserDetail>("sp_password_get", new
            {
                authUser.UserId,
                MobileNo = authUser.Mobile,
                authUser.EmailId
            });

            if (loginDetail != null)
            {
                encryptedPassword = loginDetail.Password;
                authUser.OrganizationId = loginDetail.OrganizationId;
                authUser.CompanyId = loginDetail.CompanyId;
                authUser.CompanyName = loginDetail.CompanyName;
            }
            else
            {
                throw new HiringBellException("Fail to retrieve user detail.", "UserDetail", JsonConvert.SerializeObject(authUser));
            }

            return encryptedPassword;
        }
        public async Task<AuthResponse> FetchAuthenticatedProviderDetail(UserDetail authUser)
        {
            string ProcedureName = string.Empty;
            if (authUser.UserTypeId == (int)UserType.Admin)
                ProcedureName = "sp_Userlogin_Auth";
            else if (authUser.UserTypeId == (int)UserType.Employee)
                ProcedureName = "sp_Employeelogin_Auth";
            else
                throw new HiringBellException("UserType is invalid. Only system user allowed");

            AuthResponse loginResponse = default;
            if ((!string.IsNullOrEmpty(authUser.EmailId) || !string.IsNullOrEmpty(authUser.Mobile)) && !string.IsNullOrEmpty(authUser.Password))
            {
                loginResponse = await FetchUserDetail(authUser, ProcedureName);
            }

            return loginResponse;
        }

        public async Task<AuthResponse> AuthenticateUser(SignInRequestModel signInRequest)
        {
            AuthResponse loginResponse = default;
            if ((!string.IsNullOrEmpty(signInRequest.Email) || !string.IsNullOrEmpty(signInRequest.Mobile)) && !string.IsNullOrEmpty(signInRequest.Password))
            {
                var userDetail = this.GetUserLoginDetail(signInRequest);
                var encryptedPassword = UtilService.Decrypt(userDetail.Password, _configuration.GetSection("EncryptSecret").Value);
                if (encryptedPassword.CompareTo(signInRequest.Password) != 0)
                {
                    throw HiringBellException.ThrowBadRequest("Invalid userId or password.");
                }

                loginResponse = await FetchUserDetail(userDetail, "sp_Employeelogin_Auth");

                if (await CheckOrganizationSetup())
                {
                    loginResponse.SetupStatus = true;
                }
                else
                {
                    loginResponse.SetupStatus = false;
                }

            }

            return await Task.FromResult(loginResponse);
        }

        private async Task<bool> CheckOrganizationSetup()
        {
            DbResult result = db.Execute("sp_org_setup_isready", new { CompanyId = 0 }, true);
            if (result.statusMessage == "2")
            {
                return await Task.FromResult(true);
            }

            return await Task.FromResult(false);
        }

        private async Task<AuthResponse> FetchUserDetail(UserDetail authUser, string ProcedureName)
        {
            AuthResponse loginResponse = default;
            DataSet ds = await db.GetDataSetAsync(ProcedureName, new
            {
                authUser.UserId,
                MobileNo = authUser.Mobile,
                authUser.EmailId,
                authUser.UserTypeId,
                PageSize = 50
            });

            if (ds != null && ds.Tables.Count == 8)
            {
                if (ds.Tables[0].Rows.Count > 0)
                {
                    loginResponse = new AuthResponse();
                    var loginDetail = Converter.ToType<LoginDetail>(ds.Tables[0]);
                    loginResponse.Menu = ds.Tables[1];
                    if (loginResponse.Menu.Rows.Count == 0)
                    {
                        throw HiringBellException.ThrowBadRequest("Menu not found for the current user.");
                    }

                    loginResponse.Department = ds.Tables[3];
                    loginResponse.Roles = ds.Tables[4];
                    loginResponse.UserTypeId = authUser.UserTypeId;
                    var companies = Converter.ToList<Organization>(ds.Tables[5]);
                    Files file = Converter.ToType<Files>(ds.Tables[7]);
                    if (ds.Tables[6].Rows.Count > 0 && ds.Tables[6].Rows[0][1] != DBNull.Value)
                    {
                        loginResponse.UserLayoutConfiguration =
                            JsonConvert.DeserializeObject<UserLayoutConfigurationJSON>(ds.Tables[6].Rows[0][1].ToString());
                    }

                    loginResponse.Companies = companies.FindAll(x => x.OrganizationId == loginDetail.OrganizationId);
                    var currentCompany = loginResponse.Companies.Find(x => x.CompanyId == loginDetail.CompanyId);
                    currentCompany.LogoPath = @$"{file.FilePath}\{file.FileName}";
                    loginResponse.EmployeeList = ds.Tables[2].AsEnumerable()
                                                   .Select(x => new AutoCompleteEmployees
                                                   {
                                                       value = x.Field<long>("I"),
                                                       text = x.Field<string>("N"),
                                                       email = x.Field<string>("E"),
                                                       selected = false,
                                                       DesignationId = x.Field<int>("D")
                                                   }).ToList<AutoCompleteEmployees>();

                    if (loginDetail != null && currentCompany != null)
                    {
                        var session = new CurrentSession
                        {
                            UserId = loginDetail.UserId,
                            EmployeeCodeLength = currentCompany.EmployeeCodeLength,
                            EmployeeCodePrefix = currentCompany.EmployeeCodePrefix,
                            ReportingManagerId = loginDetail.ReportingManagerId,
                            ManagerEmail = loginDetail.ManagerEmailId,
                            RoleId = loginDetail.RoleId,
                            Email = loginDetail.EmailId,
                            Mobile = loginDetail.Mobile,
                            FullName = $"{loginDetail.FirstName} {loginDetail.LastName}".Trim(),
                            ManagerName = loginDetail.ManagerName,
                            FinancialStartYear = currentCompany.FinancialYear,
                            OrganizationId = currentCompany.OrganizationId,
                            DesignationId = loginDetail.DesignationId,
                            CompanyId = currentCompany.CompanyId,
                            CompanyName = currentCompany.CompanyName
                        };


                        var userDetail = new UserDetail
                        {
                            FirstName = loginDetail.FirstName,
                            LastName = loginDetail.LastName,
                            Address = loginDetail.Address,
                            Mobile = loginDetail.Mobile,
                            EmailId = loginDetail.EmailId,
                            ManagerEmailId = loginDetail.ManagerEmailId,
                            UserId = loginDetail.UserId,
                            CompanyName = currentCompany.CompanyName,
                            UserTypeId = loginDetail.UserTypeId,
                            OrganizationId = loginDetail.OrganizationId,
                            CompanyId = loginDetail.CompanyId,
                            DesignationId = loginDetail.DesignationId,
                            ManagerName = loginDetail.ManagerName,
                            ReportingManagerId = loginDetail.ReportingManagerId,
                            UpdatedOn = loginDetail.UpdatedOn,
                            EmployeeCurrentRegime = loginDetail.EmployeeCurrentRegime,
                            DOB = loginDetail.DOB,
                            CreatedOn = loginDetail.CreatedOn,
                            WorkShiftId = loginDetail.WorkShiftId,
                            RoleId = loginDetail.RoleId,
                            CompanyCode = authUser.CompanyCode,
                            FinancialYear = currentCompany.FinancialYear,
                            EmployeeCodeLength = currentCompany.EmployeeCodeLength,
                            EmployeeCodePrefix = currentCompany.EmployeeCodePrefix,
                        };

                        loginResponse.UserDetail = userDetail;
                        var _token = await _authenticationService.Authenticate(session);
                        if (_token != null)
                        {
                            userDetail.Token = _token.Token;
                            userDetail.TokenExpiryDuration = DateTime.UtcNow.AddSeconds(_publicKeyDetail.DefaulExpiryTimeInSeconds * 12);
                            userDetail.RefreshToken = _token.RefreshToken;
                        }
                    }
                    else
                    {
                        throw HiringBellException.ThrowBadRequest("Fail to get user detail. Please contact to admin.");
                    }
                }
            }

            return loginResponse;
        }

        public string ResetEmployeePassword(UserDetail authUser)
        {
            string Status = string.Empty;
            var encryptedPassword = this.FetchUserLoginDetail(authUser);
            encryptedPassword = UtilService.Decrypt(encryptedPassword, _configuration.GetSection("EncryptSecret").Value);
            if (encryptedPassword != authUser.Password)
                throw new HiringBellException("Incorrect old password");

            string newEncryptedPassword = UtilService.Encrypt(authUser.NewPassword, _configuration.GetSection("EncryptSecret").Value);
            var result = db.Execute<string>("sp_Reset_Password", new
            {
                authUser.EmailId,
                MobileNo = authUser.Mobile,
                NewPassword = newEncryptedPassword,
                UserTypeId = (int)UserType.Employee
            }, true);

            if (result == ApplicationConstants.Updated)
            {
                Status = "Password changed successfully, Please logout and login again";
            }
            else
            {
                throw new HiringBellException("Unable to update your password");
            }

            return Status;
        }

        public async Task<bool> RegisterNewCompany(RegistrationForm registrationForm)
        {
            return await Task.Run(() =>
            {
                bool statusFlag = false;
                if (string.IsNullOrEmpty(registrationForm.OrganizationName))
                    throw new HiringBellException { UserMessage = $"Invalid Organization name passed: {registrationForm.OrganizationName}" };

                if (string.IsNullOrEmpty(registrationForm.CompanyName))
                    throw new HiringBellException { UserMessage = $"Invalid Company name passed: {registrationForm.CompanyName}" };

                if (string.IsNullOrEmpty(registrationForm.Mobile))
                    throw new HiringBellException { UserMessage = $"Invalid Mobile number: {registrationForm.Mobile}" };

                if (string.IsNullOrEmpty(registrationForm.EmailId))
                    throw new HiringBellException { UserMessage = $"Invalid Email address passed: {registrationForm.EmailId}" };

                if (string.IsNullOrEmpty(registrationForm.AuthenticationCode))
                    throw new HiringBellException { UserMessage = $"Invalid Authentication Code passed: {registrationForm.AuthenticationCode}" };

                registrationForm.FirstName = "Admin";
                registrationForm.LastName = "User";
                string EncreptedPassword = UtilService.Encrypt(
                    _configuration.GetSection("DefaultNewEmployeePassword").Value,
                    _configuration.GetSection("EncryptSecret").Value
                );
                registrationForm.Password = EncreptedPassword;

                var status = this.db.Execute<string>(Procedures.New_Registration, new
                {
                    registrationForm.OrganizationName,
                    registrationForm.CompanyName,
                    registrationForm.Mobile,
                    registrationForm.EmailId,
                    registrationForm.FirstName,
                    registrationForm.LastName,
                    registrationForm.Password
                }, true);

                statusFlag = true;
                return statusFlag;
            });
        }

        public async Task<string> ForgotPasswordService(string email)
        {
            try
            {
                string Status = string.Empty;
                ValidateEmailId(email);
                UserDetail authUser = new UserDetail();
                authUser.EmailId = email;
                var encryptedPassword = this.FetchUserLoginDetail(authUser);

                if (string.IsNullOrEmpty(encryptedPassword))
                    throw new HiringBellException("Email id is not registered. Please contact to admin");

                string newPassword = await GenerateRandomPassword(10);
                var enNewPassword = UtilService.Encrypt(newPassword, _configuration.GetSection("EncryptSecret").Value);

                var result = db.Execute<string>("sp_Reset_Password", new
                {
                    authUser.EmailId,
                    MobileNo = authUser.Mobile,
                    NewPassword = enNewPassword,
                    UserTypeId = 101
                }, true);

                if (result.ToLower() != ApplicationConstants.Updated)
                {
                    throw new HiringBellException("Unable to reset your password");
                }

                //await _forgotPasswordEmailService.SendForgotPasswordEmail(password, email);
                ForgotPasswordTemplateModel forgotPasswordTemplateModel = new ForgotPasswordTemplateModel
                {
                    CompanyName = authUser.CompanyName,
                    NewPassword = newPassword,
                    ToAddress = new List<string> { email },
                    kafkaServiceName = KafkaServiceName.ForgotPassword,
                    LocalConnectionString = _currentSession.LocalConnectionString,
                };

                await _kafkaProducerService.SendEmailNotification(forgotPasswordTemplateModel, KafkaTopicNames.ATTENDANCE_REQUEST_ACTION);
                Status = ApplicationConstants.Successfull;
                return Status;
            }
            catch (Exception)
            {
                throw new HiringBellException("Getting some server error. Please contact to admin.");
            }
        }

        private void ValidateEmailId(string email)
        {
            if (string.IsNullOrEmpty(email))
                throw new HiringBellException("Email is null or empty");

            var mail = new MailAddress(email);
            bool isValidEmail = mail.Host.Contains(".");
            if (!isValidEmail)
                throw new HiringBellException("The email is invalid");
        }

        public async Task<Tuple<string, string>> GenerateNewRegistrationPassword()
        {
            string newPassword = await GenerateRandomPassword(10);
            string encryptedPassword = UtilService.Encrypt(newPassword, _configuration.GetSection("EncryptSecret").Value);
            return new Tuple<string, string>(newPassword, encryptedPassword);
        }

        public async Task<string> EncryptDetailService(string text)
        {
            string data = UtilService.Encrypt(text, _configuration.GetSection("EncryptSecret").Value);
            return await Task.FromResult(data);
        }

        public async Task<string> DecryptDetailService(string text)
        {
            var data = UtilService.Decrypt(text, _configuration.GetSection("EncryptSecret").Value);
            return await Task.FromResult(data);
        }

        public async Task<string> GenerateRandomPassword(int length)
        {
            const string upperCaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowerCaseChars = "abcdefghijklmnopqrstuvwxyz";
            const string numericChars = "0123456789";
            const string specialChars = "!@#$%^&*-_+=";

            if (length < 6 || length > 16)
            {
                throw new ArgumentOutOfRangeException("length", "Password length should be between 8 and 16 characters.");
            }

            Random random = new Random();

            // Ensure at least one character from each character set
            char upperCaseChar = upperCaseChars[random.Next(upperCaseChars.Length)];
            char lowerCaseChar = lowerCaseChars[random.Next(lowerCaseChars.Length)];
            char numericChar = numericChars[random.Next(numericChars.Length)];
            char specialChar = specialChars[random.Next(specialChars.Length)];

            // Combine characters from all character sets
            string allChars = upperCaseChars + lowerCaseChars + numericChars + specialChars;

            // Generate the remaining characters randomly
            string randomChars = new string(Enumerable.Repeat(allChars, length - 4)
                .Select(s => s[random.Next(s.Length)]).ToArray());

            // Shuffle the characters to ensure randomness
            string combinedChars = new string(new[] { upperCaseChar, lowerCaseChar, numericChar, specialChar }.Concat(randomChars).OrderBy(c => random.Next()).ToArray());

            // Ensure that the password starts with a character
            if (char.IsDigit(combinedChars[0]))
            {
                // Swap the first digit with a random character
                char randomStartChar = allChars[random.Next(allChars.Length)];
                combinedChars = randomStartChar + combinedChars.Substring(1);
            }

            return await Task.FromResult(combinedChars);
        }

        public async Task<string> ReGenerateTokenService()
        {
            UserDetail userDetail = db.Get<UserDetail>("sp_employee_only_by_id", new { EmployeeId = 1, IsActive = true });
            userDetail.RoleId = 1;
            userDetail.CompanyCode = _currentSession.CompanyCode;
            userDetail.EmailId = userDetail.Email;
            userDetail.OrganizationId = 1;

            var session = new CurrentSession
            {
                UserId = userDetail.UserId,
                EmployeeCodeLength = userDetail.EmployeeCodeLength,
                EmployeeCodePrefix = userDetail.EmployeeCodePrefix,
                ReportingManagerId = userDetail.ReportingManagerId,
                ManagerEmail = userDetail.ManagerEmailId,
                RoleId = userDetail.RoleId,
                Email = userDetail.EmailId,
                Mobile = userDetail.Mobile,
                FullName = $"{userDetail.FirstName} {userDetail.FirstName}".Trim(),
                ManagerName = userDetail.ManagerName,
                FinancialStartYear = userDetail.FinancialYear,
                CompanyCode = userDetail.CompanyCode,
            };

            var refreshTokenModal = await _authenticationService.Authenticate(session);
            return await Task.FromResult(refreshTokenModal.Token);
        }
    }
}

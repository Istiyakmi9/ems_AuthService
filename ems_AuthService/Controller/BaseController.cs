using Bt.Ems.Lib.PipelineConfig.Model.ExceptionModel;
using Bt.Ems.Lib.User.Db.Model.MicroserviceModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net;

namespace ems_AuthService.Controller
{
    [Authorize]
    public abstract class BaseController : ControllerBase
    {
        protected ApiResponse apiResponse;
        protected string responseMessage = string.Empty;
        public BaseController()
        {
            apiResponse = new ApiResponse();
        }

        [NonAction]
        public EmstumException Throw(Exception ex, dynamic request = null)
        {
            return new EmstumException(ex.Message, JsonConvert.SerializeObject(request), ex);
        }

        [NonAction]
        public EmstumException Throw(EmstumException ex, dynamic request = null)
        {
            return new EmstumException(ex.UserMessage, JsonConvert.SerializeObject(request), ex);
        }

        [NonAction]
        public async Task<ApiResponse> BuildResponseAsync(dynamic Data, HttpStatusCode httpStatusCode = HttpStatusCode.OK, string Resion = null, string Token = null)
        {
            apiResponse.AuthenticationToken = Token;
            apiResponse.HttpStatusMessage = Resion;
            apiResponse.HttpStatusCode = httpStatusCode;
            apiResponse.ResponseBody = Data;
            return await Task.FromResult(apiResponse);
        }

        [NonAction]
        public ApiResponse GenerateResponse(HttpStatusCode httpStatusCode, dynamic Data = null)
        {
            apiResponse.HttpStatusCode = httpStatusCode;
            apiResponse.ResponseBody = Data;
            return apiResponse;
        }
    }
}

using Bt.Ems.Lib.ApiModels.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModalLayer.Modal;
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
        public HiringBellException Throw(Exception ex, dynamic request = null)
        {
            try
            {
                HiringBellException exception = (HiringBellException)ex;
                return new HiringBellException(exception.UserMessage, JsonConvert.SerializeObject(request), ex);
            }
            catch
            {
                Console.WriteLine("This is not a HiringBellException");
            }

            return new HiringBellException(ex.Message, JsonConvert.SerializeObject(request), ex);
        }

        [NonAction]
        public ApiResponse BuildResponse(dynamic Data, HttpStatusCode httpStatusCode = HttpStatusCode.OK, string Resion = null, string Token = null)
        {
            apiResponse.AuthenticationToken = Token;
            apiResponse.HttpStatusMessage = Resion;
            apiResponse.HttpStatusCode = httpStatusCode;
            apiResponse.ResponseBody = Data;
            return apiResponse;
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

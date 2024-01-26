using System.Net;

namespace ems_AuthServiceLayer.Service
{
    [Serializable]
    public class HiringBellException : Exception
    {
        public string UserMessage { get; set; }

        public HttpStatusCode HttpStatusCode { get; set; } = HttpStatusCode.BadRequest;


        public string FieldName { get; set; }

        public string FieldValue { get; set; }

        public string StackTraceDetail { get; set; }

        public HiringBellException()
        {
        }

        public HiringBellException(string Message, Exception InnerException)
            : base(Message, InnerException)
        {
            UserMessage = Message;
            StackTraceDetail = ((InnerException != null) ? InnerException.StackTrace : "");
            HttpStatusCode = HttpStatusCode.BadRequest;
        }

        public HiringBellException(string Message, HttpStatusCode httpStatusCode)
        {
            UserMessage = Message;
            HttpStatusCode = httpStatusCode;
        }

        public HiringBellException(string Message, string FieldName = null, string FieldValue = null, HttpStatusCode httpStatusCode = HttpStatusCode.BadRequest)
        {
            UserMessage = Message;
            this.FieldName = FieldName;
            this.FieldValue = FieldValue;
            HttpStatusCode = httpStatusCode;
        }

        public HiringBellException BuildBadRequest(string Message, string Field = null, string Value = null)
        {
            HttpStatusCode = HttpStatusCode.BadRequest;
            UserMessage = Message + " Field: " + Field + ", Value: " + Value;
            FieldName = Field;
            FieldValue = Value;
            return this;
        }

        public HiringBellException BuildNotFound(string Message, string Filed = null, string Value = null)
        {
            HttpStatusCode = HttpStatusCode.NotFound;
            UserMessage = Message;
            FieldName = Filed;
            FieldValue = Value;
            return this;
        }

        public static HiringBellException ThrowBadRequest(string Message, HttpStatusCode httpStatusCode = HttpStatusCode.BadRequest)
        {
            return new HiringBellException(Message, httpStatusCode);
        }
    }
}

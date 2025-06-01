using Bot.CoreBottomHalf.CommonModal;
using System.Data;
using UserDetail = Bt.Ems.Lib.User.Db.Model.UserDetail;

namespace ems_AuthServiceLayer.Models
{
    public class AuthResponse
    {
        public UserDetail UserDetail { get; set; }
        public DataTable Menu { get; set; }
        public List<CompanyDetail> Companies { get; set; }
        public int UserTypeId { get; set; }
        public DataTable Department { get; set; }
        public DataTable Roles { get; set; }
        public List<AutoCompleteEmployees> EmployeeList { get; set; }
        public bool SetupStatus { set; get; }
        public UserLayoutConfigurationJSON UserLayoutConfiguration { get; set; }
    }
}

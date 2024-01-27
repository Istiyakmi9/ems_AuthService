namespace ems_AuthServiceLayer.Models
{
    public class ApplicationSettings
    {
        public int ApplicationSettingId { set; get; }
        public int OrganizationId { set; get; }
        public int CompanyId { set; get; }
        public int SettingsCatagoryId { set; get; }
        public string SettingDetails { set; get; }
    }
}

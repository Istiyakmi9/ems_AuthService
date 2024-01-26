namespace ems_AuthServiceLayer.Models
{
    public class DbConfigModal
    {
        public string OrganizationCode { set; get; }
        public string Code { set; get; }
        public string Schema { set; get; }
        public string DatabaseName { set; get; }
        public string Server { set; get; }
        public string Port { set; get; }
        public string Database { set; get; }
        public string UserId { set; get; }
        public string Password { set; get; }
        public int ConnectionTimeout { set; get; }
        public int ConnectionLifetime { set; get; }
        public int MinPoolSize { set; get; }
        public int MaxPoolSize { set; get; }
        public bool Pooling { set; get; }
    }
}

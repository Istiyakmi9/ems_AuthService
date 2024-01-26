namespace ems_AuthServiceLayer.Models
{
    public enum UserType
    {
        Admin = 1,
        Employee = 2,
        Candidate = 3,
        Client = 4,
        Other = 5,
        Compnay = 6,
        Organization = 7
    }

    public enum Environments
    {
        Development,
        Production,
        Staging
    }
}

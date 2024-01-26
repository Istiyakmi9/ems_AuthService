namespace ems_AuthServiceLayer.Service
{
    public struct Role
    {
        public const string Admin = "Admin";
        public const string Employee = "Employee";
        public const string Manager = "Manager";
        public const string ManagerWithAdmin = Admin + "," + Manager;
        public const string EmployeeWithAdmin = Admin + "," + Employee;
        public const string AllRole = Admin + "," + Employee + "," + Manager;
    }

    public enum Roles
    {
        Admin = 1,
        ProjectManager = 2,
        ProjectArchitect = 3,
        Tester = 4,
        SeniorHR = 5,
        HR = 6,
        Manager = 7,
        SolutionArchitect = 8,
        ApplicationArchitect = 9,
        Networking = 10,
        TestLead = 11,
        FullStackDeveloper = 12,
        Developer = 13,
        SrSoftwareDeveloper = 14,
        DatabaseDeveloper = 15,
        FrontendDeveloper = 16,
        SystemEngineer = 17,
        AssociateEngineer = 18,
        TeamLead = 19,
        Other = 20
    }
}

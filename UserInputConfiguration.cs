namespace FHIRClient;

public class UserInputConfiguration
{
    private Patient[] _patients = null!;
    private User[] _users = null!;
    private Org _organization = null!;

    public Patient[] Patients
    {
        get => _patients;
        set => _patients = value;
    }

    public User[] Users
    {
        get => _users;
        set => _users = value;
    }

    public Org Organization
    {
        get => _organization;
        set => _organization = value;
    }

    public class Patient
    {
        private string _Name = null!;
        private string _INSZ = null!;
        private string _identifier = null!;
        private string _identifierSystem = null!;

        public string Name
        {
            get => _Name;
            set => _Name = value;
        }
        public string INSZ
        {
            get => _INSZ;
            set => _INSZ = value;
        }

        public string Identifier
        {
            get => _identifier;
            set => _identifier = value;
        }

        public string IdentifierSystem
        {
            get => _identifierSystem;
            set => _identifierSystem = value;
        }

        public override string ToString()
        {
            return _Name + " (" + _INSZ + ")";
        }

    }

    public class User
    {
        private string _Title = null!;
        private string _LastName = null!;
        private string _GivenName = null!;
        private string _Role = null!;
        private string _RIZIV = null!;
        private string _INSZ = null!;

        public string Title
        {
            get => _Title;
            set => _Title = value;
        }

        public string LastName
        {
            get => _LastName;
            set => _LastName = value;
        }

        public string GivenName
        {
            get => _GivenName;
            set => _GivenName = value;
        }

        public string INSZ
        {
            get => _INSZ;
            set => _INSZ = value;
        }

        public string Role
        {
            get => _Role;
            set => _Role = value;
        }

        public string RIZIV
        {
            get => _RIZIV;
            set => _RIZIV = value;
        }

        public override string ToString()
        {
            return _LastName + " " + _GivenName + " (" + _Role + ")";
        }
    }

    public class Org
    {
        private string _Name = null!;
        private string _RIZIV = null!;

        public string Name
        {
            get => _Name;
            set => _Name = value;
        }

        public string RIZIV
        {
            get => _RIZIV;
            set => _RIZIV = value;
        }
    }


}
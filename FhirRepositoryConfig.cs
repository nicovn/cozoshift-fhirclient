namespace FHIRClient;

public class FhirRepositoryConfig
{

    private string _name = null!;
    private string _fhirEndpoint = null!;
    private string _oauthTokenEndpoint = null!;
    private string _oauthClientId = null!;
    private string _oauthScopes = null!;
    private string _jwkSetUrl = null!;
    private string _jwkSetKeyId = null!;
    private string _rsaPrivateKeyPEMEncoded = null!;
    private int _maxResultsPerPage = 200;
    private string _keystoreFile = null!;
    private string _keystoreFilePassword = null!;
    private UserInputConfiguration _userInputDefaults = null!;

    public string Name
    {
        get => _name;
        set => _name = value;
    }

    public string FhirEndpoint
    {
        get => _fhirEndpoint;
        set => _fhirEndpoint = value;
    }

    public string OauthTokenEndpoint
    {
        get => _oauthTokenEndpoint;
        set => _oauthTokenEndpoint = value;
    }

    public string OauthClientId
    {
        get => _oauthClientId;
        set => _oauthClientId = value;
    }

    public string OauthScopes
    {
        get => _oauthScopes;
        set => _oauthScopes = value;
    }

    public string JwkSetUrl
    {
        get => _jwkSetUrl;
        set => _jwkSetUrl = value;
    }

    public string JwkSetKeyId
    {
        get => _jwkSetKeyId;
        set => _jwkSetKeyId = value;
    }

    public string RsaPrivateKeyPEMEncoded
    {
        get => _rsaPrivateKeyPEMEncoded;
        set => _rsaPrivateKeyPEMEncoded = value;
    }

    public int MaxResultsPerPage
    {
        get => _maxResultsPerPage;
        set => _maxResultsPerPage = value;
    }

    public string KeystoreFile
    {
        get => _keystoreFile;
        set => _keystoreFile = value;
    }

    public string KeystoreFilePassword
    {
        get => _keystoreFilePassword;
        set => _keystoreFilePassword = value;
    }

    public UserInputConfiguration UserInputDefaults
    {
        get => _userInputDefaults;
        set => _userInputDefaults = value;
    }

}
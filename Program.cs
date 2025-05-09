namespace FHIRClient;

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Claims;
using Hl7.Fhir.Model;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;
using IdentityModel.Client;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1; // For DerObjectIdentifier
using Org.BouncyCastle.Asn1.X9; // For ECNamedCurveTable, X9ECParameters
using Org.BouncyCastle.Math; // For BigInteger
using Jose;
using System.Collections.Immutable;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.X509;
using Sharprompt;
using System.Dynamic;
using System.ComponentModel.DataAnnotations;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Runtime.Versioning;
using Org.BouncyCastle.Utilities.IO.Pem;
using Hl7.Fhir.Specification;
using Hl7.Fhir.Specification.Source;
using Hl7.Fhir.Specification.Terminology;
using Firely.Fhir.Packages;
using Firely.Fhir.Validation;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;

class Program
{
    static async System.Threading.Tasks.Task Main(string[] args)
    {
        // configuration data - FHIR repository
        FhirRepositoryConfig fhirRepositoryConfig = null!;

        var baseFilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\CoZoSHIFT";
        if (!Directory.Exists(baseFilePath))
        {
            Directory.CreateDirectory(baseFilePath);
        }
        var correlationId = Guid.NewGuid().ToString();

        var fhirRepositoryConfigFile = baseFilePath + @"\fhir-repository-config.json";

        // serialize JSON directly to a file
        if (!File.Exists(fhirRepositoryConfigFile))
        {

            var fhirRepositoryConfigDefault = new FhirRepositoryConfig()
            {
                Name = "Name of your FHIR Repository",
                FhirEndpoint = "https://fhirserver.org/fhir-server/api/v4",
                OauthTokenEndpoint = "https://fhirserver.org/oauth2/token",
                OauthClientId = "",
                OauthScopes = "system/Organization.cruds system/Practitioner.cruds system/PractitionerRole.cruds system/Patient.cruds system/Condition.cruds",
                JwkSetUrl = "https://api-acpt.ehealth.fgov.be/etee/v1/pubKeys/cacerts/jwks?identifier=<riziv-hospital>&type=NIHII-HOSPITAL&use=sig",
                JwkSetKeyId = "",
                KeystoreFile = baseFilePath + @"NIHII-HOSPITAL=xxxxxx 20220415-104753.acc-p12",
                KeystoreFilePassword = "",
                MaxResultsPerPage = 200
            };

            fhirRepositoryConfig = fhirRepositoryConfigDefault;

            // store the repo configuration a file
            using (StreamWriter file = File.CreateText(fhirRepositoryConfigFile))
            {
                JsonSerializer serializer = new JsonSerializer();
                serializer.Formatting = Formatting.Indented;
                serializer.Serialize(file, fhirRepositoryConfig);

            }
        }
        else
        {
            var jsonRepositoryConfig = File.ReadAllText(fhirRepositoryConfigFile);
            if (jsonRepositoryConfig != null)
            {
                fhirRepositoryConfig = System.Text.Json.JsonSerializer.Deserialize<FhirRepositoryConfig>(jsonRepositoryConfig)!;
            }
        }

        if ((fhirRepositoryConfig.OauthClientId == "") || (fhirRepositoryConfig.OauthClientId == null))
        {
            Console.WriteLine("Incomplete repository configuration - please update file " + fhirRepositoryConfigFile);
            Console.WriteLine("Press any key to stop...");
            Console.ReadKey();
            System.Environment.Exit(-1);
        }

        if ((fhirRepositoryConfig.JwkSetKeyId == "") || (fhirRepositoryConfig.JwkSetKeyId == null))
        {
            Console.WriteLine("Incomplete repository configuration - please update file " + fhirRepositoryConfigFile);
            Console.WriteLine("Press any key to stop...");
            Console.ReadKey();
            System.Environment.Exit(-1);
        }

        Console.WriteLine(new string('-', 80));
        Console.WriteLine("Download meest recente versie van FHIRClient via : " + "https://cozoshift.s3.eu-central-1.amazonaws.com/FHIRClient.exe");
        Console.WriteLine("Repository configuratie bestand: " + fhirRepositoryConfigFile);
        Console.WriteLine("Gedetailleerde log bestanden worden opgeslagen in bestand " + baseFilePath + @"\logs\" + correlationId + ".txt");
        Console.WriteLine("FHIR endpoint: " + fhirRepositoryConfig.FhirEndpoint);
        Console.WriteLine("OAuth token endpoint: " + fhirRepositoryConfig.OauthTokenEndpoint);
        Console.WriteLine(new string('-', 80));
        Console.WriteLine("\r\n");

        // collect end user properties
        // configuration data - end user properties -- https://github.com/shibayan/Sharprompt
        bool userSelected = false;
        string subjectRoleCode = "";
        string userIdType = "";
        string userIdentifierValue = "";
        string userIdentifierSystem = "";
        string subjectName = "";

        bool organizationSelected = false;
        string subjectOrganization = "";
        string subjectOrganizationIdentifierValue = "";
        string subjectOrganizationIdentifierSystem = "https://www.ehealth.fgov.be/standards/fhir/core/NamingSystem/nihdi";

        bool patientSelected = false;
        string patientIdentifier = "";
        string patientIdentifierSystem = "https://www.ehealth.fgov.be/standards/fhir/core/NamingSystem/ssin";


        if (fhirRepositoryConfig.UserInputDefaults != null)
        {
            if ((fhirRepositoryConfig.UserInputDefaults.Users != null) && (fhirRepositoryConfig.UserInputDefaults.Users.Length > 0))
            {
                var user = Prompt.Select("Selecteer gebruiker", fhirRepositoryConfig.UserInputDefaults.Users);
                subjectRoleCode = user.Role;
                if ((user.RIZIV != null) && (user.RIZIV != ""))
                {
                    userIdType = "RIZIVNR";
                    userIdentifierValue = user.RIZIV;
                    userIdentifierSystem = "https://www.ehealth.fgov.be/standards/fhir/core/NamingSystem/nihdi";
                }
                else
                {
                    userIdType = "INSZ";
                    userIdentifierValue = user.INSZ;
                    userIdentifierSystem = "https://www.ehealth.fgov.be/standards/fhir/core/NamingSystem/ssin";
                }
                subjectName = user.LastName + " " + user.GivenName;
                userSelected = true;
            }

            if (fhirRepositoryConfig.UserInputDefaults.Organization != null)
            {
                subjectOrganization = fhirRepositoryConfig.UserInputDefaults.Organization.Name;
                subjectOrganizationIdentifierValue = fhirRepositoryConfig.UserInputDefaults.Organization.RIZIV;
                organizationSelected = true;
            }

            if ((fhirRepositoryConfig.UserInputDefaults.Patients != null) && (fhirRepositoryConfig.UserInputDefaults.Patients.Length > 0))
            {
                var patient = Prompt.Select("Selecteer patient", fhirRepositoryConfig.UserInputDefaults.Patients);
                if ((patient.INSZ != null) && (patient.INSZ != ""))
                {
                    patientIdentifier = patient.INSZ;
                    patientIdentifierSystem = "https://www.ehealth.fgov.be/standards/fhir/core/NamingSystem/ssin";
                    patientSelected = true;
                }
                else
                {
                    if ((patient.Identifier != null) && (patient.Identifier != "") && (patient.IdentifierSystem != null) && (patient.IdentifierSystem != ""))
                    {
                        patientIdentifier = patient.Identifier;
                        patientIdentifierSystem = patient.IdentifierSystem;
                        patientSelected = true;
                    }
                }
            }
        }

        if (!userSelected)
        {
            subjectRoleCode = Prompt.Select("Type gebruiker", new[] { "persphysician", "persnurse", "perspharmacist", "persdentist" });
            userIdType = Prompt.Select("Gebruiker identificatienummer type", new[] { "INSZ", "RIZIVNR" });

            if (userIdType == "INSZ")
            {
                userIdentifierSystem = "https://www.ehealth.fgov.be/standards/fhir/core/NamingSystem/ssin";
                userIdentifierValue = Prompt.Input<string>("Gebruiker INSZ", defaultValue: "", validators: new[] { Validators.Required(), Validators.MinLength(11) });
            }
            else
            {
                userIdentifierValue = Prompt.Input<string>("Gebruiker RIZIV nummer ", defaultValue: "10828465123", validators: new[] { Validators.Required(), Validators.MinLength(11) });
                userIdentifierSystem = "https://www.ehealth.fgov.be/standards/fhir/core/NamingSystem/nihdi";
            }

            subjectName = Prompt.Input<string>("Naam gebruiker: ", defaultValue: "Naam van de zorgverlener");

        }

        if (!organizationSelected)
        {
            subjectOrganization = Prompt.Input<string>("Instelling: ", defaultValue: "Amaron Ziekenhuis");
            subjectOrganizationIdentifierValue = Prompt.Input<string>("RIZIV nummer instelling: ", defaultValue: "71045471", validators: new[] { Validators.Required(), Validators.MinLength(8), Validators.MaxLength(8) });
        }

        var subjectRoleSystem = "https://www.ehealth.fgov.be/standards/fhir/core/CodeSystem/cd-hcparty";
        var subjectRoleDisplay = "";

        switch (subjectRoleCode)
        {
            case "persphysician":
                subjectRoleDisplay = "arts";
                break;
            case "persnurse":
                subjectRoleDisplay = "verpleegkundige";
                break;
            case "persmidwife":
                subjectRoleDisplay = "vroedvrouw";
                break;
            case "persclinicalbiologist":
                subjectRoleDisplay = "klinisch bioloog";
                break;
            case "perspharmacist":
                subjectRoleDisplay = "apotheker";
                break;
            case "persdentist":
                subjectRoleDisplay = "tandarts";
                break;
            default:
                subjectRoleDisplay = "onbekend";
                break;
        }
        var purposeOfUseSystem = "http://terminology.hl7.org/CodeSystem/v3-ActReason";
        var purposeOfUseCode = "PATADMIN";
        var purposeOfUseDisplay = "Patient administration";

        // configuration data - Patient search query
        //var patientSearchQueryString = Prompt.Input<string>("Patient search query: ", defaultValue: "identifier=urn:oid:1.2.840.114350.1.13.0.1.7.5.737384.14|203713");


        if (!patientSelected)
        {
            if (fhirRepositoryConfig.FhirEndpoint == "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/")
            {
                patientIdentifier = Prompt.Input<string>("EPIC Patient identifier: ", defaultValue: "203713");
                patientIdentifierSystem = "urn:oid:1.2.840.114350.1.13.0.1.7.5.737384.14";
            }
            else
            {
                patientIdentifier = Prompt.Input<string>("Patient INSZ: ", defaultValue: "01482105560");
            }
        }



        var typeFHIRQuery = Prompt.Select("Type FHIR query", new[] { "Allergien", "Problemen/Antecedenten", "Custom" });
        var fhirResourceName = "";
        var defaultQueryString = System.Web.HttpUtility.ParseQueryString(string.Empty);

        switch (typeFHIRQuery)
        {
            case "Allergien":
                fhirResourceName = "AllergyIntolerance";
                //defaultQueryString.Add("patient:Patient.organization:Organization.identifier", subjectOrganizationIdentifierSystem + "|" + subjectOrganizationIdentifierValue);
                defaultQueryString.Add("patient:Patient.identifier", patientIdentifierSystem + "|" + patientIdentifier);
                defaultQueryString.Add("_include:iterate", "PractitionerRole:practitioner");
                defaultQueryString.Add("_include:iterate", "PractitionerRole:organization");
                defaultQueryString.Add("_include:iterate", "Patient:organization");
                defaultQueryString.Add("_include", "AllergyIntolerance:recorder");
                defaultQueryString.Add("_include", "AllergyIntolerance:patient");

                break;

            case "Problemen/Antecedenten":
                fhirResourceName = "Condition";
                //defaultQueryString.Add("patient:Patient.organization:Organization.identifier", subjectOrganizationIdentifierSystem + "|" + subjectOrganizationIdentifierValue);
                defaultQueryString.Add("patient:Patient.identifier", patientIdentifierSystem + "|" + patientIdentifier);
                defaultQueryString.Add("_include:iterate", "PractitionerRole:practitioner");
                defaultQueryString.Add("_include:iterate", "PractitionerRole:organization");
                defaultQueryString.Add("_include:iterate", "Patient:organization");
                defaultQueryString.Add("_include", "Condition:asserter");
                defaultQueryString.Add("_include", "Condition:patient");

                break;

            case "Custom":
                fhirResourceName = Prompt.Input<string>("Resource: ", defaultValue: "");
                break;

        }

        // Add specific query parameters for FHIRStation debugging
        if ((fhirRepositoryConfig.FhirEndpoint.EndsWith("/fhirstation-rest/api/fhir")) ||
            (fhirRepositoryConfig.FhirEndpoint.EndsWith("/fhirstation-rest/api/fhir/")))
        {
            defaultQueryString.Add("_AMARON_tracing", "true");
            defaultQueryString.Add("_AMARON_tracing_payload", "true");
        }

        var defaultSearchQueryString = System.Web.HttpUtility.UrlDecode(defaultQueryString.ToString());
        if (fhirResourceName != "")
        {
            Console.WriteLine("Path = /" + fhirResourceName);
        }

        var searchQueryString = Prompt.Input<string>("Search query string: ", defaultValue: defaultSearchQueryString);

        WriteToLog(baseFilePath, correlationId, "Search query string: " + searchQueryString);
        WriteToLog(baseFilePath, correlationId, "");

        // END configuration data

        var searchQueryNameValueCollection = System.Web.HttpUtility.ParseQueryString(searchQueryString);
        var queryParameters = new List<string>();
        for (int i = 0; i < searchQueryNameValueCollection.Count; i++)
        {
            var parameterName = searchQueryNameValueCollection.GetKey(i);
            if (searchQueryNameValueCollection.GetValues(i) != null)
            {
                string[] parameterValues = searchQueryNameValueCollection.GetValues(i)!;
                foreach (string paramValue in parameterValues)
                {
                    queryParameters.Add(parameterName + "=" + paramValue);

                }
            }
        }

        var tokenClient = new HttpClient(new LoggingHandler(new HttpClientHandler(), baseFilePath, correlationId));

        var now = DateTimeOffset.UtcNow;

        var issuedAtDateTime = now.AddSeconds(-10);
        // Belangrijk voor EPIC - expiration date moet minder dan 5 minuten zijn !
        // https://fhir.epic.com/Resources/jwt_auth_troubleshoot_eof
        var expires = now.AddMinutes(2);

        long lIat = (long)Convert.ToDouble(issuedAtDateTime.ToUnixTimeSeconds().ToString());
        long lExp = (long)Convert.ToDouble(expires.ToUnixTimeSeconds().ToString());

        var subjectRole = new
        {
            system = subjectRoleSystem,
            code = subjectRoleCode,
            display = subjectRoleDisplay
        };

        object[] subjectRoles = new object[1];
        subjectRoles[0] = subjectRole;

        var purposeOfUse = new
        {
            system = purposeOfUseSystem,
            code = purposeOfUseCode,
            display = purposeOfUseDisplay
        };
        object[] purposeOfUses = new object[1];
        purposeOfUses[0] = purposeOfUse;

        var iheIUA = new
        {
            person_id = patientIdentifierSystem + "|" + patientIdentifier,
            national_provider_identifier = userIdentifierSystem + "|" + userIdentifierValue,
            subject_name = subjectName,
            subject_organization = subjectOrganization,
            subject_organization_id = subjectOrganizationIdentifierSystem + "|" + subjectOrganizationIdentifierValue,
            subject_role = subjectRoles,
            purpose_of_use = purposeOfUses,

        };

        var extensions = new { ihe_iua = iheIUA };

        var claimsPayload = new Dictionary<string, object>()
            {
                {"iss", fhirRepositoryConfig.OauthClientId},
                {"aud", fhirRepositoryConfig.OauthTokenEndpoint},
                {"sub", fhirRepositoryConfig.OauthClientId},
                {"iat", lIat},
                {"exp", lExp},
                {"jti", Guid.NewGuid().ToString()},
                {"extensions", extensions}
        };


        var clientAssertion = CreateAuthenticationJWT(claimsPayload, fhirRepositoryConfig);
        TokenResponse? tokenResponse = null;
        if (clientAssertion != null)
        {
            WriteToLog(baseFilePath, correlationId, "Generated client_assertion (JWT): " + clientAssertion);

            var cli = new ClientAssertion();
            cli.Value = clientAssertion;
            cli.Type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

            tokenResponse = await tokenClient.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Address = fhirRepositoryConfig.OauthTokenEndpoint,
                ClientId = fhirRepositoryConfig.OauthClientId,
                ClientAssertion = cli,
                Scope = fhirRepositoryConfig.OauthScopes,
            });
        }

        using (var handler = new HttpClientEventHandler())
        {
            var settings = new FhirClientSettings
            {
                PreferredFormat = ResourceFormat.Json,
                Timeout = 30000,
            };
            using (FhirClient client = new FhirClient(fhirRepositoryConfig.FhirEndpoint, settings: settings, messageHandler: handler))
            {
                // use strict serializer (https://docs.fire.ly/projects/Firely-NET-SDK/en/stable/client/setup.html#fhirclient-communication-options)
                client.WithStrictSerializer();

                handler.OnBeforeRequest += async (sender, e) =>
                {
                    if (tokenResponse != null)
                    {
                        e.RawRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
                    }

                    // Generate a Provenance FHIR resource - to send in a header
                    var provenance = new Provenance();
                    provenance.Id = Guid.NewGuid().ToString();
                    var resReference = new ResourceReference();
                    resReference.Display = "Search operation executed by an end user";
                    provenance.Target.Add(resReference);
                    provenance.Occurred = new FhirDateTime(DateTime.Now);
                    provenance.Recorded = new FhirDateTime(DateTime.Now).ToDateTimeOffset(TimeSpan.Zero);
                    provenance.Policy = new List<string> { "https://www.cozo.be/ehealthic" };
                    var reasonCode = new CodeableConcept().Add(purposeOfUseSystem, purposeOfUseCode, purposeOfUseDisplay);
                    reasonCode.Text = purposeOfUseDisplay;
                    provenance.Reason.Add(reasonCode);
                    var agentComponent = new Provenance.AgentComponent();
                    agentComponent.Type = new CodeableConcept().Add("http://terminology.hl7.org/CodeSystem/provenance-participant-type", "enterer", "");
                    var roleCode = new CodeableConcept().Add(subjectRoleSystem, subjectRoleCode, subjectRoleDisplay);
                    roleCode.Text = subjectRoleDisplay;
                    agentComponent.Role.Add(roleCode);

                    var resReferenceWho = new ResourceReference();
                    resReferenceWho.Type = "Practitioner";
                    resReferenceWho.Identifier = new Identifier();
                    resReferenceWho.Identifier.System = userIdentifierSystem;
                    resReferenceWho.Identifier.Value = userIdentifierValue;
                    resReferenceWho.Display = subjectName;
                    agentComponent.Who = resReferenceWho;

                    var resReferenceOnBehalfOf = new ResourceReference();
                    resReferenceOnBehalfOf.Type = "Organization";
                    resReferenceOnBehalfOf.Identifier = new Identifier();
                    resReferenceOnBehalfOf.Identifier.System = subjectOrganizationIdentifierSystem;
                    resReferenceOnBehalfOf.Identifier.Value = subjectOrganizationIdentifierValue;
                    resReferenceOnBehalfOf.Display = subjectOrganization;
                    agentComponent.OnBehalfOf = resReferenceOnBehalfOf;


                    provenance.Agent.Add(agentComponent);

                    var FhirJsonSerializer = new FhirJsonSerializer();
                    var jsProvenance = await FhirJsonSerializer.SerializeToStringAsync(provenance);

                    WriteToLog(baseFilePath, correlationId, "Generated Provenance resource: " + jsProvenance);

                    e.RawRequest.Headers.Add("X-Provenance", jsProvenance);

                    // LOG http request
                    WriteToLog(baseFilePath, correlationId, "");
                    WriteToLog(baseFilePath, correlationId, new string('-', 80));
                    WriteToLog(baseFilePath, correlationId, "HTTP Request:");
                    WriteToLog(baseFilePath, correlationId, e.RawRequest.ToString());
                    if (e.RawRequest.Content != null)
                    {
                        WriteToLog(baseFilePath, correlationId, await e.RawRequest.Content.ReadAsStringAsync());
                    }
                    WriteToLog(baseFilePath, correlationId, "");
                };

                handler.OnAfterResponse += async (sender, e) =>
                {
                    // LOG http response
                    WriteToLog(baseFilePath, correlationId, "Received HTTP response from FHIR endpoint " + fhirRepositoryConfig.FhirEndpoint);
                    WriteToLog(baseFilePath, correlationId, e.RawResponse.ToString());
                    if (e.RawResponse.Content != null)
                    {
                        string httpResponseBody = await e.RawResponse.Content.ReadAsStringAsync();
                        //WriteToLog(baseFilePath, correlationId, e.RawResponse.Content.ReadAsStringAsync());
                        WriteToLog(baseFilePath, correlationId, httpResponseBody);
                    }
                    WriteToLog(baseFilePath, correlationId, new string('-', 80));
                    WriteToLog(baseFilePath, correlationId, "");
                };

                try
                {
                    var results = await client.SearchUsingPostAsync(fhirResourceName, queryParameters.ToArray(), pageSize: fhirRepositoryConfig.MaxResultsPerPage);

                    if (results != null)
                    {
                        WriteToLog(baseFilePath, correlationId, "Formatted JSON response:");
                        WriteToLog(baseFilePath, correlationId, "");
                        WriteToLog(baseFilePath, correlationId, JToken.Parse(results.ToJson()).ToString(Formatting.Indented));

                        await ValidateResourceAgainstBEProfile(baseFilePath, correlationId, client, results);

                        await FetchConditionsPractitionerRole(client, results);

                        while (results != null)
                        {
                            results = await client.ContinueAsync(results);
                            if (results != null)
                            {
                                WriteToLog(baseFilePath, correlationId, "Next page fetched");
                                WriteToLog(baseFilePath, correlationId, JToken.Parse(results.ToJson()).ToString(Formatting.Indented));

                                await FetchConditionsPractitionerRole(client, results);
                            }
                        }
                    }
                }
                catch (Exception foe)
                {
                    WriteToLog(baseFilePath, correlationId, "Unable to execute FHIR query - " + foe);
                }

            }
        }

        Console.WriteLine("\r\n");
        Console.WriteLine("Gedetailleerde logging is te vinden in bestand " + baseFilePath + @"\logs\" + correlationId + ".txt");

        Console.WriteLine("Press any key to stop...");
        Console.ReadKey();

    }

    private static async Task<bool> FetchConditionsPractitionerRole(FhirClient client, Hl7.Fhir.Model.Bundle resultBundle)
    {
        var practitionerRoleFetched = false;
        var conditionResourcePresent = false;

        foreach (var e in resultBundle.Entry)
        {
            if (e.Resource != null)
            {
                if (e.Resource.TypeName == "Condition")
                {
                    var condition_entry = (Condition)e.Resource;
                    if ((condition_entry != null) &&
                            (condition_entry.Recorder != null) &&
                            (condition_entry.Recorder.ReferenceElement != null))
                    {
                        conditionResourcePresent = true;
                        try
                        {
                            if ((condition_entry.Meta != null) && (condition_entry.Meta.Source != null) && (condition_entry.Meta.Source != ""))
                            {
                                var defaultQueryString = System.Web.HttpUtility.ParseQueryString(string.Empty);
                                var sourceMetaField = condition_entry.Meta.Source;
                                if (sourceMetaField.Contains('#'))
                                {
                                    sourceMetaField = sourceMetaField.Substring(0, sourceMetaField.IndexOf('#'));
                                }
                                defaultQueryString.Add("_source", sourceMetaField);
                                var recorderResourceIdRef = condition_entry.Recorder.ReferenceElement.Value;
                                var recorderResourceIdRefItems = recorderResourceIdRef.Split("/");
                                defaultQueryString.Add("_id", recorderResourceIdRefItems[1]);
                                var searchQueryString = System.Web.HttpUtility.UrlDecode(defaultQueryString.ToString());
                                if (searchQueryString != null)
                                {
                                    var searchQueryNameValueCollection = System.Web.HttpUtility.ParseQueryString(searchQueryString);
                                    var queryParameters = new List<string>();
                                    for (int i = 0; i < searchQueryNameValueCollection.Count; i++)
                                    {
                                        var parameterName = searchQueryNameValueCollection.GetKey(i);
                                        if (searchQueryNameValueCollection.GetValues(i) != null)
                                        {
                                            string[] parameterValues = searchQueryNameValueCollection.GetValues(i)!;
                                            foreach (string paramValue in parameterValues)
                                            {
                                                queryParameters.Add(parameterName + "=" + paramValue);
                                            }
                                        }
                                    }

                                    var results = await client.SearchUsingPostAsync("PractitionerRole", queryParameters.ToArray());
                                    if (results != null)
                                    {
                                        foreach (var re in results.Entry)
                                        {
                                            if (re.Resource != null)
                                            {
                                                if (re.Resource.TypeName == "PractitionerRole")
                                                {
                                                    practitionerRoleFetched = true;
                                                }
                                            }
                                        }

                                    }
                                }
                            }
                            else
                            {
                                var refRecorder = condition_entry.Recorder.Url;
                                Console.WriteLine("Fetching condition recorder (PractitionerRole) " + refRecorder);
                                var practitionerRole = await client.ReadAsync<PractitionerRole>(refRecorder);

                                if (practitionerRole != null)
                                {
                                    practitionerRoleFetched = true;
                                }

                            }


                        }
                        catch (Exception foe)
                        {
                            Console.WriteLine("Unable to fetch PractitionerRole - " + foe);
                        }

                    }

                }

            }
        }


        if ((conditionResourcePresent) && (!practitionerRoleFetched))
        {
            Console.WriteLine("ERROR - Unable to fetch PractitionerRole");
        }

        return practitionerRoleFetched;
    }

    private static async Task<bool> ValidateResourceAgainstBEProfile(string baseFilePath, string correlationId, FhirClient client, Hl7.Fhir.Model.Bundle resultBundle)
    {
        var validatedAgainstProfile = false;
        var conditionResourcePresent = false;

        foreach (var e in resultBundle.Entry)
        {
            if (e.Resource != null)
            {
                if (e.Resource.TypeName == "Condition")
                {
                    var condition_entry = (Condition)e.Resource;
                    if (condition_entry != null)
                    {
                        conditionResourcePresent = true;
                        try
                        {
                            //var packageServerUrl = "https://packages.simplifier.net";
                            var packageServerUrl = "https://registry.fhir.org";
                            var fhirRelease = FhirRelease.R4;

                            var packageResolver = FhirPackageSource.CreateCorePackageSource(ModelInfo.ModelInspector, fhirRelease, packageServerUrl);
                            var resourceResolver = new CachedResolver(packageResolver);

                            Hl7.Fhir.Specification.Source.IAsyncResourceResolver resolver = new CachedResolver(
                                new MultiResolver(
                                    //ZipSource.CreateValidationSource(),
                                    new DirectorySource("Profiles", new DirectorySourceSettings()
                                    {
                                        IncludeSubDirectories = true,
                                    }),
                                    resourceResolver
                                //new WebResolver()
                                )
                            );

                            //var terminologyService = new LocalTerminologyService(resourceResolver);
                            var terminologyService = new LocalTerminologyService(resolver);
                            var settings = new FhirClientSettings
                            {
                                PreferredFormat = ResourceFormat.Json,
                                Timeout = 30000,
                            };

                            //var terminolgyClient = new FhirClient("https://mirthtraining-aws.nicovn.net/fhir-subscription/", settings: settings);
                            var terminolgyClient = new FhirClient("https://tx.fhir.org/r4", settings: settings);

                            var extTerminology = new ExternalTerminologyService(terminolgyClient);

                            /*
                            Hl7.Fhir.Model.Parameters parameters = new Hl7.Fhir.Model.Parameters();
                            parameters.
                            var dummy = await extTerminology.Lookup(null, false);
                            */

                            var multiTermService = new MultiTerminologyService(extTerminology, terminologyService);

                            var validator = new Firely.Fhir.Validation.Validator(resolver, terminologyService);
                            //var validator = new Firely.Fhir.Validation.Validator(resolver, multiTermService);
                            //var validator = new Firely.Fhir.Validation.Validator(resolver, extTerminology);

                            var result = validator.Validate(condition_entry);

                            WriteToLog(baseFilePath, correlationId, "Profile validation result : (" + condition_entry + ") " + result);

                            Console.WriteLine(result);

                        }
                        catch (Exception foe)
                        {
                            Console.WriteLine("Unable to validate resource against profile - " + foe);
                        }

                    }

                }

            }
        }

        if (conditionResourcePresent)
        {
            return validatedAgainstProfile;
        }
        else
        {
            return true;
        }
    }

    public static void WriteToLog(string baseFilePath, string correlationId, object messageToLog)
    {
        Console.WriteLine(messageToLog);

        var logPath = baseFilePath + @"\logs";
        if (!Directory.Exists(logPath))
        {
            Directory.CreateDirectory(logPath);
        }
        File.AppendAllText(logPath + @"\" + correlationId + ".txt", messageToLog + Environment.NewLine);
    }

    public static string? CreateAuthenticationJWT(Dictionary<string, object> claimsPayload, FhirRepositoryConfig fhirRepositoryConfig)
    {
        RSAParameters rsaParams;
        string jwkSetUrl = fhirRepositoryConfig.JwkSetUrl;
        string jwkSetKeyId = fhirRepositoryConfig.JwkSetKeyId;

        if ((fhirRepositoryConfig.RsaPrivateKeyPEMEncoded != null) && (fhirRepositoryConfig.RsaPrivateKeyPEMEncoded != ""))
        {
            string privateRsaKey = fhirRepositoryConfig.RsaPrivateKeyPEMEncoded;
            using (var tr = new StringReader(privateRsaKey))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(tr);
                var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                if (keyPair == null)
                {
                    throw new Exception("Could not read RSA private key");
                }
                var privateRsaParams = keyPair.Private as RsaPrivateCrtKeyParameters;
                rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);
            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);

                var jwtHeaders = new Dictionary<string, object>();
                jwtHeaders.Add("typ", "JWT");
                jwtHeaders.Add("kid", jwkSetKeyId);
                jwtHeaders.Add("jku", jwkSetUrl);

                String encodedJWT = Jose.JWT.Encode(claimsPayload, rsa, Jose.JwsAlgorithm.RS256, jwtHeaders);
                return encodedJWT;
            }

        }
        else
        {
            if ((fhirRepositoryConfig.KeystoreFile != null) && (fhirRepositoryConfig.KeystoreFile != ""))
            {
                string keystoreFilePassword = null!;
                if ((fhirRepositoryConfig.KeystoreFilePassword != null) && (fhirRepositoryConfig.KeystoreFilePassword != ""))
                {
                    keystoreFilePassword = fhirRepositoryConfig.KeystoreFilePassword;
                }
                else
                {
                    keystoreFilePassword = Prompt.Password("Keystore file password: ");
                }

                Org.BouncyCastle.Pkcs.Pkcs12Store pkcs = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder().Build();

                using (System.IO.Stream stream = new System.IO.FileStream(fhirRepositoryConfig.KeystoreFile, System.IO.FileMode.Open,
                System.IO.FileAccess.Read, System.IO.FileShare.Read))
                {
                    if (keystoreFilePassword != null)
                    {
                        pkcs.Load(stream, keystoreFilePassword.ToCharArray());
                    }
                    else
                    {
                        pkcs.Load(stream, "".ToCharArray());
                    }

                } // End Using stream 

                Org.BouncyCastle.Pkcs.AsymmetricKeyEntry keyEntry = null!;
                // Belgische ehealth keystores hebben een 'authentication' alias
                if (pkcs.ContainsAlias("authentication"))
                {
                    keyEntry = pkcs.GetKey("authentication");
                }
                else
                {
                    foreach (string alias in pkcs.Aliases)
                    {
                        if (pkcs.IsKeyEntry((string)alias))
                        {
                            keyEntry = pkcs.GetKey(alias);
                        }
                    }
                }

                if (keyEntry != null)
                {
                    Org.BouncyCastle.Crypto.AsymmetricKeyParameter privateKey = keyEntry.Key;

                    if (privateKey.GetType().ToString().Equals("Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters"))
                    {
                        var privateRsaParams = privateKey as RsaPrivateCrtKeyParameters;

                        rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);

                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                        {
                            rsa.ImportParameters(rsaParams);

                            var jwtHeaders = new Dictionary<string, object>();
                            jwtHeaders.Add("typ", "JWT");
                            jwtHeaders.Add("kid", jwkSetKeyId);
                            jwtHeaders.Add("jku", jwkSetUrl);

                            String encodedJWT = Jose.JWT.Encode(claimsPayload, rsa, Jose.JwsAlgorithm.RS256, jwtHeaders);
                            return encodedJWT;
                        }
                    }
                    else
                    {
                        if (privateKey.GetType().ToString().Equals("Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters"))
                        {
                            var privateECParams = privateKey as ECPrivateKeyParameters;

                            if (privateECParams != null)
                            {
                                ECDsa ecdsaKey = ConvertBcPrivateKeyToNetECDsa(privateECParams);
                                var jwtHeaders = new Dictionary<string, object>();
                                jwtHeaders.Add("typ", "JWT");
                                jwtHeaders.Add("kid", jwkSetKeyId);
                                jwtHeaders.Add("jku", jwkSetUrl);

                                String encodedJWT = Jose.JWT.Encode(claimsPayload, ecdsaKey, Jose.JwsAlgorithm.ES384, jwtHeaders);

                                return encodedJWT;
                            }
                        }
                        else
                        {
                            throw new Exception("Unsupported private key type " + privateKey.GetType().ToString());
                        }

                    }



                }
            }

            return null;
        }

    }

    private static ECDsa ConvertBcPrivateKeyToNetECDsa(ECPrivateKeyParameters bcPrivateKey)
    {
        if (bcPrivateKey == null)
            throw new ArgumentNullException(nameof(bcPrivateKey));

        // 1. Extract Private Key Scalar (D)
        // Use ToByteArrayUnsigned to get the minimal big-endian representation.
        byte[] dBytes = bcPrivateKey.D.ToByteArrayUnsigned();

        // 2. Determine the Elliptic Curve OID
        DerObjectIdentifier curveOid = null;

        if (bcPrivateKey.PublicKeyParamSet != null)
        {
            curveOid = bcPrivateKey.PublicKeyParamSet;
        }
        else if (bcPrivateKey.Parameters != null)
        {
            // Try to find a matching named curve by comparing domain parameters
            ECDomainParameters bcDomainParams = bcPrivateKey.Parameters;
            foreach (string name in ECNamedCurveTable.Names)
            {
                X9ECParameters x9Params = ECNamedCurveTable.GetByName(name);
                if (x9Params.Curve.Equals(bcDomainParams.Curve) &&
                    x9Params.G.Equals(bcDomainParams.G) &&
                    x9Params.N.Equals(bcDomainParams.N) &&
                    ((x9Params.H == null && bcDomainParams.H == null) || (x9Params.H != null && x9Params.H.Equals(bcDomainParams.H)))) // H can be null or 1
                {
                    curveOid = ECNamedCurveTable.GetOid(name);
                    break;
                }
            }
        }

        if (curveOid == null)
        {
            throw new NotSupportedException("Could not determine the curve OID from the Bouncy Castle private key. Explicit curve parameter conversion may be required.");
        }

        // 3. Create System.Security.Cryptography.ECCurve
        ECCurve eccCurve;
        string oidValue = curveOid.Id;
        string friendlyNameFromBc = ECNamedCurveTable.GetName(curveOid); // Bouncy Castle's name for the OID

        try
        {
            // Use Oid class, providing friendlyName is good practice for debugging/logging
            System.Security.Cryptography.Oid netOid = new System.Security.Cryptography.Oid(oidValue, friendlyNameFromBc ?? oidValue);
            eccCurve = ECCurve.CreateFromOid(netOid);
        }
        catch (CryptographicException ex)
        {
            // Fallback for common NIST curves if CreateFromOid fails with BC's friendly name
            // or if .NET expects a slightly different friendly name.
            // .NET often uses names like "nistP256" for "secp256r1"/"prime256v1".
            if (oidValue == X9ObjectIdentifiers.Prime256v1.Id) // secp256r1
                eccCurve = ECCurve.NamedCurves.nistP256;
            else if (oidValue == SecNamedCurves.GetOid("secp384r1").Id)
                eccCurve = ECCurve.NamedCurves.nistP384;
            else if (oidValue == SecNamedCurves.GetOid("secp521r1").Id)
                eccCurve = ECCurve.NamedCurves.nistP521;
            else
            {
                throw new NotSupportedException($"Curve with OID {oidValue} (Friendly Name: {friendlyNameFromBc}) could not be mapped to a .NET ECCurve.", ex);
            }
        }

        // 4. Populate System.Security.Cryptography.ECParameters
        ECParameters ecParams = new ECParameters
        {
            D = dBytes,
            Curve = eccCurve
        };

        // Optionally, derive and set the public key Q.
        // ECDsa.ImportParameters can derive Q, but it's good to be explicit.
        ECDomainParameters domainParamsToDeriveQ = bcPrivateKey.Parameters;
        if (domainParamsToDeriveQ == null && curveOid != null) // If only OID was available initially
        {
            X9ECParameters x9Params = ECNamedCurveTable.GetByOid(curveOid);
            if (x9Params != null)
            {
                domainParamsToDeriveQ = new ECDomainParameters(x9Params.Curve, x9Params.G, x9Params.N, x9Params.H, x9Params.GetSeed());
            }
        }

        if (domainParamsToDeriveQ != null)
        {
            Org.BouncyCastle.Math.EC.ECPoint qPublicPoint = domainParamsToDeriveQ.G.Multiply(bcPrivateKey.D);

            // *** FIX: Normalize the point before accessing affine coordinates ***
            if (qPublicPoint != null && !qPublicPoint.IsNormalized())
            {
                qPublicPoint = qPublicPoint.Normalize();
            }

            // Ensure qPublicPoint is not null after potential normalization or if G.Multiply resulted in infinity (unlikely for valid private keys)
            if (qPublicPoint == null || qPublicPoint.IsInfinity)
            {
                throw new CryptographicException("Failed to derive a valid public key point (possibly resulted in point at infinity).");
            }

            ecParams.Q = new ECPoint // System.Security.Cryptography.ECPoint
            {
                X = qPublicPoint.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(),
                Y = qPublicPoint.AffineYCoord.ToBigInteger().ToByteArrayUnsigned()
            };
        }
        else
        {
            // If Q cannot be derived here, .NET's ImportParameters will attempt to derive it.
            // Log or handle this case if Q is strictly needed upfront.
            // Consider throwing an exception if domain parameters are essential and missing.
            Console.WriteLine("Warning: Could not obtain domain parameters to derive public key Q explicitly; relying on .NET to derive it during import if possible.");
        }

        // 5. Import into System.Security.Cryptography.ECDsa
        ECDsa ecdsa = ECDsa.Create(); // Creates a default ECDsa implementation (e.g., ECDsaCng on Windows, ECDsaOpenSsl on Linux)

        try
        {
            ecdsa.ImportParameters(ecParams);
        }
        catch (CryptographicException ex)
        {
            // This can happen if D is invalid for the curve, or Q is malformed/inconsistent.
            throw new CryptographicException("Failed to import ECParameters into ECDsa object. " +
                                             $"Ensure curve is supported and parameters are valid. D length: {dBytes.Length}, " +
                                             $"Curve: {eccCurve.Oid?.FriendlyName ?? eccCurve.CurveType.ToString()}", ex);
        }

        return ecdsa;
    }

}

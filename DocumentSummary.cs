using System.Reflection;

public class DocumentSummary
{
    private string _id = null!;
    private string _facility = null;
    private string _identifier = null!;
    private string _identifierSystem = null!;
    private string _documentDate = null;
    private string _title = null;
    private List<DocumentContent> _documentContents = new List<DocumentContent>();

    public string Id
    {
        get => _id;
        set => _id = value;
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

    public string Facility
    {
        get => _facility;
        set => _facility = value;
    }

    public string DocumentDate
    {
        get => _documentDate;
        set => _documentDate = value;
    }

    public string Title
    {
        get => _title;
        set => _title = value;
    }

    public List<DocumentContent> DocumentContents
    {
        get => _documentContents;
        set => _documentContents = value;
    }

    public override string ToString()
    {
        return _documentDate + ": " + _title + " (" + _facility + ") (" + _identifier + ")";
    }

    public class DocumentContent
    {
        private string _url = null!;
        private string _format = null!;

        public DocumentContent(string url, string format)
        {
            _url = url;
            _format = format;
        }

        public string Url
        {
            get => _url;
            set => _url = value;
        }

        public override string ToString()
        {
            return _url + ": " + " (" + _format + ")";
        }
    }
}
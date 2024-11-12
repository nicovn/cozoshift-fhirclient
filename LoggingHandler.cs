namespace FHIRClient;

public class LoggingHandler : DelegatingHandler
{
    private string _baseFilePath;
    private string _correlationId;


    public LoggingHandler(HttpMessageHandler innerHandler, string baseFilePath, string correlationId)
        : base(innerHandler)
    {
        _baseFilePath = baseFilePath;
        _correlationId = correlationId;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        WriteToLog();
        WriteToLog(new string('-', 80));
        WriteToLog("HTTP Request:");
        WriteToLog(request.ToString());
        if (request.Content != null)
        {
            WriteToLog(await request.Content.ReadAsStringAsync());
        }
        WriteToLog();

        HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

        WriteToLog("HTTP Response:");
        WriteToLog(response.ToString());
        if (response.Content != null)
        {
            WriteToLog(await response.Content.ReadAsStringAsync());
        }
        WriteToLog(new string('-', 80));
        WriteToLog();

        return response;
    }

    public void WriteToLog(object messageToLog)
    {
        Console.WriteLine(messageToLog);

        var logPath = _baseFilePath + @"\logs";
        if (!Directory.Exists(logPath))
        {
            Directory.CreateDirectory(logPath);
        }
        File.AppendAllText(logPath + @"\" + _correlationId + ".txt", messageToLog + Environment.NewLine);
    }

    public void WriteToLog()
    {
        Console.WriteLine();

        var logPath = _baseFilePath + @"\logs";
        if (!Directory.Exists(logPath))
        {
            Directory.CreateDirectory(logPath);
        }
        File.AppendAllText(logPath + @"\" + _correlationId + ".txt", Environment.NewLine);
    }
}
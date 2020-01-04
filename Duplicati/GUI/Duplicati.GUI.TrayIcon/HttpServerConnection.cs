using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Duplicati.Library.Common.IO;
using Duplicati.Server.Serialization;
using Duplicati.Server.Serialization.Interface;

namespace Duplicati.GUI.TrayIcon
{
    public class HttpServerConnection : IDisposable
    {
        private static readonly Encoding ENCODING = Encoding.UTF8;
        private static readonly string LOGTAG = Library.Logging.Log.LogTagFromType<HttpServerConnection>();
        private const string LOGIN_SCRIPT = "login.cgi";
        private const string STATUS_WINDOW = "index.html";

        private const string XSRF_COOKIE = "xsrf-token";
        private const string XSRF_HEADER = "X-XSRF-Token";
        private const string AUTH_COOKIE = "session-auth";

        private const string TRAYICONPASSWORDSOURCE_HEADER = "X-TrayIcon-PasswordSource";
        
        private class BackgroundRequest
        {
            public readonly HttpMethod Method;
            public readonly string Endpoint;
            public readonly Dictionary<string, string> Query;

            public BackgroundRequest(HttpMethod method, string endpoint, Dictionary<string, string> query)
            {
                this.Method = method;
                this.Endpoint = endpoint;
                this.Query = query;
            }
        }

        private readonly string m_baseUri;
        private string m_password;
        private readonly bool m_saltedpassword;
        private string m_authtoken;
        private string m_xsrftoken;

        public delegate void StatusUpdateDelegate(IServerStatus status);
        public event StatusUpdateDelegate OnStatusUpdated;

        public long m_lastNotificationId = -1;
        public DateTime m_firstNotificationTime;
        public delegate void NewNotificationDelegate(INotification notification);
        public event NewNotificationDelegate OnNotification;

        private long m_lastDataUpdateId = -1;
        private bool m_disableTrayIconLogin;

        private volatile IServerStatus m_status;

        private volatile bool m_shutdown = false;
        private volatile Thread m_requestThread;
        private volatile Thread m_pollThread;
        private readonly AutoResetEvent m_waitLock;

        private readonly Dictionary<string, string> m_updateRequest;
        private readonly Dictionary<string, string> m_options;
        private readonly Program.PasswordSource m_passwordSource;

        public IServerStatus Status { get { return m_status; } }

        private readonly object m_lock = new object();
        private readonly Queue<BackgroundRequest> m_workQueue = new Queue<BackgroundRequest>();

        private readonly CookieContainer m_cookies;
        private readonly HttpClient m_client;

        public HttpServerConnection(Uri server, string password, bool saltedpassword, Program.PasswordSource passwordSource, bool disableTrayIconLogin, Dictionary<string, string> options)
        {
            m_baseUri = Util.AppendDirSeparator(server.ToString(), "/");

            string trayIconHeaderValue = (m_passwordSource == Program.PasswordSource.Database) ? "database" : "user";
            string versionString = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();

            m_cookies = new CookieContainer();
            var handler = new HttpClientHandler { CookieContainer = m_cookies };
            m_client = new HttpClient(handler)
            {
                BaseAddress = new Uri(m_baseUri + "api/v1/"),
                DefaultRequestHeaders =
                {
                    { TRAYICONPASSWORDSOURCE_HEADER, trayIconHeaderValue }
                }
            };

            m_client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DuplicatiTrayIcon", versionString));

            m_disableTrayIconLogin = disableTrayIconLogin;

            m_firstNotificationTime = DateTime.Now;

            m_password = password;
            m_saltedpassword = saltedpassword;
            m_options = options;
            m_passwordSource = passwordSource;

            m_updateRequest = new Dictionary<string, string>();
            m_updateRequest["longpoll"] = "false";
            m_updateRequest["lasteventid"] = "0";

            UpdateStatus();

            //We do the first request without long poll,
            // and all the rest with longpoll
            m_updateRequest["longpoll"] = "true";
            m_updateRequest["duration"] = "5m";
            
            m_waitLock = new AutoResetEvent(false);
            m_requestThread = new Thread(ThreadRunner);
            m_pollThread = new Thread(LongPollRunner);

            m_requestThread.Name = "TrayIcon Request Thread";
            m_pollThread.Name = "TrayIcon Longpoll Thread";

            m_requestThread.Start();
            m_pollThread.Start();
        }

        private void UpdateStatus()
        {
            m_status = PerformRequest<IServerStatus>(HttpMethod.Get, "serverstate", m_updateRequest).Result;
            m_updateRequest["lasteventid"] = m_status.LastEventID.ToString();

            OnStatusUpdated?.Invoke(m_status);

            if (m_lastNotificationId != m_status.LastNotificationUpdateID)
            {
                m_lastNotificationId = m_status.LastNotificationUpdateID;
                UpdateNotifications();
            }

            if (m_lastDataUpdateId != m_status.LastDataUpdateID)
            {
                m_lastDataUpdateId = m_status.LastDataUpdateID;
                UpdateApplicationSettings();
            }
        }

        private void UpdateNotifications()
        {
            var notifications = PerformRequest<INotification[]>(HttpMethod.Get, "notifications").Result;
            if (notifications != null)
            {
                foreach(var n in notifications.Where(x => x.Timestamp > m_firstNotificationTime))
                    if (OnNotification != null)
                        OnNotification(n);

                if (notifications.Any())
                    m_firstNotificationTime = notifications.Select(x => x.Timestamp).Max();
            }
        }

        private void UpdateApplicationSettings()
        {
            var settings = PerformRequest<Dictionary<string, string>>(HttpMethod.Get, "serversettings").Result;
            if (settings != null && settings.TryGetValue("disable-tray-icon-login", out string disableTrayIconLogoValue))
                m_disableTrayIconLogin = Library.Utility.Utility.ParseBool(disableTrayIconLogoValue, false);
        }

        private void LongPollRunner()
        {
            while (!m_shutdown)
            {
                try
                {
                    UpdateStatus();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine("Request error: " + ex.Message);
					Library.Logging.Log.WriteWarningMessage(LOGTAG, "TrayIconRequestError", ex, "Failed to get response");
                }
            }
        }

        private void ThreadRunner()
        {
            while (!m_shutdown)
            {
                try
                {
                    BackgroundRequest req;
                    bool any = false;
                    do
                    {
                        req = null;

                        lock (m_lock)
                            if (m_workQueue.Count > 0)
                                req = m_workQueue.Dequeue();

                        if (m_shutdown)
                            break;

                        if (req != null)
                        {
                            any = true;
                            PerformRequest<string>(req.Method, req.Endpoint, req.Query).Wait();
                        }
                    
                    } while (req != null);
                    
                    if (!(any || m_shutdown))
                        m_waitLock.WaitOne(TimeSpan.FromMinutes(1), true);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine("Request error: " + ex.Message);
					Library.Logging.Log.WriteWarningMessage(LOGTAG, "TrayIconRequestError", ex, "Failed to get response");
                }
            }
        }

        public void Close()
        {
            m_shutdown = true;
            m_waitLock.Set();
            m_pollThread.Abort();
            m_pollThread.Join(TimeSpan.FromSeconds(10));
            if (!m_requestThread.Join(TimeSpan.FromSeconds(10)))
            {
                m_requestThread.Abort();
                m_requestThread.Join(TimeSpan.FromSeconds(10));
            }
        }

        private static string EncodeQueryString(Dictionary<string, string> dict)
        {
            return string.Join("&", Array.ConvertAll(dict.Keys.ToArray(), key => string.Format("{0}={1}", Uri.EscapeUriString(key), Uri.EscapeUriString(dict[key]))));
        }

        private class SaltAndNonce
        {
            // ReSharper disable once FieldCanBeMadeReadOnly.Local
            // This cannot be made readonly as its value is set by a deserializer.
            public string Salt = null;
            
            // ReSharper disable once FieldCanBeMadeReadOnly.Local
            // This cannot be made readonly as its value is set by a deserializer.
            public string Nonce = null;
        }

        private async Task<SaltAndNonce> GetSaltAndNonce()
        {
            using (var httpOptions = new Library.Modules.Builtin.HttpOptions())
            {
                httpOptions.Configure(m_options);

                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, LOGIN_SCRIPT)
                {
                    Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>
                    {
                        ["get-nonce"] = "1"
                    })
                };

                HttpResponseMessage response = await m_client.SendAsync(request);
                Stream responseStream = await response.Content.ReadAsStreamAsync();
                return Serializer.Deserialize<SaltAndNonce>(responseStream);
            }
        }

        private async Task<string> PerformLogin(string password, string nonce)
        {
            using (var httpOptions = new Library.Modules.Builtin.HttpOptions())
            {
                httpOptions.Configure(m_options);

                m_cookies.Add(new Cookie("session-nonce", nonce, "/", m_client.BaseAddress.Host));

                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, LOGIN_SCRIPT)
                {
                    Content = new FormUrlEncodedContent(
                        new Dictionary<string, string>
                        {
                            ["password"] = Library.Utility.Uri.UrlEncode(password)
                        }),
                };

                HttpResponseMessage response = await m_client.SendAsync(request);
                if(response.StatusCode != HttpStatusCode.OK)
                {
                    return null;
                }

                return response.Headers.GetValues("Cookie").FirstOrDefault(c => c.StartsWith(AUTH_COOKIE));
                //return (r.Cookies[AUTH_COOKIE] ?? r.Cookies[Library.Utility.Uri.UrlEncode(AUTH_COOKIE)]).Value;
            }
        }

        private async Task<string> GetAuthToken()
        {
            if (string.IsNullOrWhiteSpace(m_password))
                return string.Empty;
            
            SHA256 sha256 = SHA256.Create();

            var salt_nonce = await GetSaltAndNonce();
            var password = m_password;

            if (!m_saltedpassword)
            {
                byte[] str = ENCODING.GetBytes(m_password);
                byte[] buf = Convert.FromBase64String(salt_nonce.Salt);
                sha256.TransformBlock(str, 0, str.Length, str, 0);
                sha256.TransformFinalBlock(buf, 0, buf.Length);
                password = Convert.ToBase64String(sha256.Hash);
                sha256.Initialize();
            }

            var nonce = Convert.FromBase64String(salt_nonce.Nonce);
            sha256.TransformBlock(nonce, 0, nonce.Length, nonce, 0);
            var pwdbuf = Convert.FromBase64String(password);
            sha256.TransformFinalBlock(pwdbuf, 0, pwdbuf.Length);
            var pwd = Convert.ToBase64String(sha256.Hash);

            return await PerformLogin(pwd, salt_nonce.Nonce);
        }

        private async Task<T> PerformRequest<T>(HttpMethod method, string endpoint, Dictionary<string, string> queryparams = null)
        {
            Debug.Assert(!endpoint.StartsWith("/"), $"Absolute endpoint '{endpoint}' provided should be relative.");

            bool hasTriedPassword = false;
            if (queryparams == null)
            {
                queryparams = new Dictionary<string, string>();
            }

            queryparams["format"] = "json";

            using var httpOptions = new Library.Modules.Builtin.HttpOptions();
            httpOptions.Configure(m_options);

            while (true)
            {
                HttpRequestMessage request = new HttpRequestMessage(
                    method,
                    new Uri(endpoint + "?" + EncodeQueryString(queryparams), UriKind.Relative));

                request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue(ENCODING.BodyName));

                if (m_xsrftoken != null)
                {
                    request.Headers.Add(XSRF_HEADER, m_xsrftoken);
                    m_cookies.Add(new Cookie(XSRF_COOKIE, m_xsrftoken, "/", m_client.BaseAddress.Host));
                }

                if (m_authtoken != null)
                    m_cookies.Add(new Cookie(AUTH_COOKIE, m_authtoken, "/", m_client.BaseAddress.Host));

                CancellationTokenSource cts = new CancellationTokenSource();

                if (endpoint.Equals("serverstate", StringComparison.OrdinalIgnoreCase) &&
                    queryparams.ContainsKey("duration"))
                {
                    //Assign the timeout, and add a little processing time as well
                    var timeout = Library.Utility.Timeparser.ParseTimeSpan(queryparams["duration"]) +
                        TimeSpan.FromSeconds(5);
                    cts.CancelAfter(timeout);
                }

                HttpResponseMessage response = await m_client.SendAsync(request, cts.Token);

                if (response.StatusCode == HttpStatusCode.BadRequest && response.ReasonPhrase.StartsWith("Missing XSRF Token"))
                {
                    string xsrfCookie = m_cookies.GetCookies(m_client.BaseAddress)[XSRF_COOKIE]?.Value;
                    m_xsrftoken = Library.Utility.Uri.UrlDecode(xsrfCookie);

                    continue;
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized && !hasTriedPassword)
                {
                    //Can survive if server password is changed via web ui
                    switch (m_passwordSource)
                    {
                        case Program.PasswordSource.Database:
                            if (Program.databaseConnection != null)
                                Program.databaseConnection.ApplicationSettings.ReloadSettings();

                            if (Program.databaseConnection != null && Program.databaseConnection.ApplicationSettings.WebserverPasswordTrayIcon != m_password)
                                m_password = Program.databaseConnection.ApplicationSettings.WebserverPasswordTrayIcon;
                            else
                                hasTriedPassword = true;
                            break;
                        case Program.PasswordSource.HostedServer:
                            if (Server.Program.DataConnection != null && Server.Program.DataConnection.ApplicationSettings.WebserverPassword != m_password)
                                m_password = Server.Program.DataConnection.ApplicationSettings.WebserverPassword;
                            else
                                hasTriedPassword = true;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }

                    m_authtoken = await GetAuthToken();
                }

                using (var s = await response.Content.ReadAsStreamAsync())
                {
                    if (typeof(T) == typeof(string))
                    {
                        using MemoryStream ms = new MemoryStream();
                        s.CopyTo(ms);
                        return (T)(object)ENCODING.GetString(ms.ToArray());
                    }
                    else
                    {
                        using var sr = new StreamReader(s, ENCODING, true);
                        return Serializer.Deserialize<T>(sr);
                    }
                }
            }
        }

        private void ExecuteAndNotify(HttpMethod method, string urifragment, Dictionary<string, string> queryParameters = null)
        {
            lock (m_lock)
            {
                m_workQueue.Enqueue(new BackgroundRequest(method, urifragment, queryParameters));
                m_waitLock.Set();
            }
        }

        public void Pause(string duration = null)
        {
            var queryParameters = new Dictionary<string, string>();
            if (!string.IsNullOrWhiteSpace(duration))
                queryParameters.Add("duration", duration);

            ExecuteAndNotify(HttpMethod.Post, "serverstate/pause", queryParameters);
        }

        public void Resume()
        {
            ExecuteAndNotify(HttpMethod.Post, "serverstate/resume");
        }

        public void StopTask(long id)
        {
            ExecuteAndNotify(HttpMethod.Post, string.Format("task/{0}/stop", Library.Utility.Uri.UrlPathEncode(id.ToString())));
        }

        public void AbortTask(long id)
        {
            ExecuteAndNotify(HttpMethod.Post, string.Format("task/{0}/abort", Library.Utility.Uri.UrlPathEncode(id.ToString())));
        }

        public void RunBackup(long id, bool forcefull = false)
        {
            var queryParameters = new Dictionary<string, string>();
            if (forcefull)
                queryParameters.Add("full", "true");
            ExecuteAndNotify(HttpMethod.Post, string.Format("backup/{0}/start", Library.Utility.Uri.UrlPathEncode(id.ToString())), queryParameters);
        }
  
        public void DismissNotification(long id)
        {
            ExecuteAndNotify(HttpMethod.Delete, string.Format("notification/{0}", Library.Utility.Uri.UrlPathEncode(id.ToString())));
        }

        public void Dispose()
        {
            Close();
        }
        
        public string StatusWindowURL
        {
            get 
            { 
                if (m_authtoken != null)
                    return m_baseUri + STATUS_WINDOW + (m_disableTrayIconLogin ? string.Empty : "?auth-token=" + GetAuthToken());
                
                return m_baseUri + STATUS_WINDOW; 
            }
        }
    }
}

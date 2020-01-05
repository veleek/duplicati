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
        private static readonly string LOGTAG = Library.Logging.Log.LogTagFromType<HttpServerConnection>();
        private const string LOGIN_SCRIPT = "/login.cgi";

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

        public delegate void StatusUpdateDelegate(IServerStatus status);
        public event StatusUpdateDelegate OnStatusUpdated;

        public long m_lastNotificationId = -1;
        public DateTime m_firstNotificationTime = DateTime.Now;
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
            m_password = password;
            m_saltedpassword = saltedpassword;
            m_passwordSource = passwordSource;
            m_disableTrayIconLogin = disableTrayIconLogin;
            m_options = options;
            
            m_cookies = new CookieContainer();
            m_client = new HttpClient(new HttpClientHandler { CookieContainer = m_cookies })
            {
                BaseAddress = new Uri(m_baseUri + "api/v1/"),
            };

            m_client.DefaultRequestHeaders.Add(TRAYICONPASSWORDSOURCE_HEADER, (m_passwordSource == Program.PasswordSource.Database) ? "database" : "user");
            m_client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DuplicatiTrayIcon", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString()));
            m_client.DefaultRequestHeaders.AcceptCharset.Add(new StringWithQualityHeaderValue(Encoding.UTF8.BodyName));

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
                    OnNotification?.Invoke(n);

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

        private async Task GetAuthToken()
        {
            if (string.IsNullOrWhiteSpace(m_password))
                return;
            
            HashAlgorithm hash = SHA256.Create();

            var salt_nonce = await GetSaltAndNonce();
            var password = m_password;

            if (!m_saltedpassword)
            {
                byte[] str = Encoding.UTF8.GetBytes(m_password);
                byte[] buf = Convert.FromBase64String(salt_nonce.Salt);
                hash.TransformBlock(str, 0, str.Length, str, 0);
                hash.TransformFinalBlock(buf, 0, buf.Length);
                password = Convert.ToBase64String(hash.Hash);
                hash.Initialize();
            }

            var nonce = Convert.FromBase64String(salt_nonce.Nonce);
            hash.TransformBlock(nonce, 0, nonce.Length, nonce, 0);
            var pwdbuf = Convert.FromBase64String(password);
            hash.TransformFinalBlock(pwdbuf, 0, pwdbuf.Length);
            var pwd = Convert.ToBase64String(hash.Hash);

            await PerformLogin(pwd);
        }

        private async Task PerformLogin(string password)
        {
            using var httpOptions = new Library.Modules.Builtin.HttpOptions();
            httpOptions.Configure(m_options);

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, LOGIN_SCRIPT)
            {
                Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>
                    {
                        ["password"] = password
                    }),
            };

            // We don't need to do anything with the response.  This request will set some 
            // cookies that will be used for future requests (if successful)
            await m_client.SendAsync(request);
        }

        private async Task<SaltAndNonce> GetSaltAndNonce()
        {
            using var httpOptions = new Library.Modules.Builtin.HttpOptions();
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

        private async Task<T> PerformRequest<T>(HttpMethod method, string endpoint, Dictionary<string, string> queryparams = null)
        {
            Debug.Assert(!endpoint.StartsWith("/"), $"Absolute endpoint '{endpoint}' provided should be relative.");

            bool hasTriedXsrf = false;
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

                if (response.StatusCode == HttpStatusCode.BadRequest && response.ReasonPhrase.StartsWith("Missing XSRF Token") && !hasTriedXsrf)
                {
                    // We don't need to do anything else.  The XSRF cookie will be added automatically if present.
                    hasTriedXsrf = true;
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

                    await GetAuthToken();
                    continue;
                }
                else
                {
                    response.EnsureSuccessStatusCode();
                }

                if (typeof(T) == typeof(string))
                {
                    string responseContent = await response.Content.ReadAsStringAsync();
                    return (T)(object)responseContent;
                }
                else
                {
                    using Stream responseStream = await response.Content.ReadAsStreamAsync();
                    return Serializer.Deserialize<T>(responseStream);
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
                const string AUTH_COOKIE = "session-auth";
                CookieCollection cookies = m_cookies.GetCookies(m_client.BaseAddress);
                var authCookie = cookies[AUTH_COOKIE] ?? cookies[Library.Utility.Uri.UrlEncode(AUTH_COOKIE)];

                if (m_disableTrayIconLogin || authCookie == null)
                    return m_baseUri;
                
                return m_baseUri + "?auth-token=" + authCookie.Value;
            }
        }
    }
}

#region Disclaimer / License
// Copyright (C) 2015, The Duplicati Team
// http://www.duplicati.com, info@duplicati.com
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
// 
#endregion
using Duplicati.Library.Common.IO;
using Duplicati.Library.Interface;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Duplicati.Library.Backend
{
    // ReSharper disable once UnusedMember.Global
    // This class is instantiated dynamically in the BackendLoader.
    public class CloudFiles : IBackend, IStreamingBackend
    {
        private const string AUTH_URL_US = "https://identity.api.rackspacecloud.com/auth";
        private const string AUTH_URL_UK = "https://lon.auth.api.rackspacecloud.com/v1.0";
        private const string DUMMY_HOSTNAME = "api.mosso.com";
        private const int ITEM_LIST_LIMIT = 1000;

        private readonly string m_path;
        private readonly HttpClient m_authClient;
        private HttpClient m_storageClient;

        private readonly byte[] m_copybuffer = new byte[Duplicati.Library.Utility.Utility.DEFAULT_BUFFER_SIZE];

        // ReSharper disable once UnusedMember.Global
        // This constructor is needed by the BackendLoader.
        public CloudFiles()
        {
        }

        // ReSharper disable once UnusedMember.Global
        // This constructor is needed by the BackendLoader.
        public CloudFiles(string url, Dictionary<string, string> options)
        {
            var uri = new Utility.Uri(url);

            string username = uri.Username;
            if (string.IsNullOrEmpty(username))
                options.TryGetValue("cloudfiles-username", out username);
            if (string.IsNullOrEmpty(username))
                options.TryGetValue("auth-username", out username);
            if (string.IsNullOrEmpty(username))
                throw new UserInformationException(Strings.CloudFiles.NoUserIDError, "CloudFilesNoUserID");

            string password = uri.Password;
            if (string.IsNullOrEmpty(password))
                options.TryGetValue("auth-password", out password);
            if (string.IsNullOrEmpty(password))
                options.TryGetValue("cloudfiles-accesskey", out password);
            if (string.IsNullOrEmpty(password))
                throw new UserInformationException(Strings.CloudFiles.NoAPIKeyError, "CloudFilesNoApiKey");

            //Fallback to the previous format
            if (url.Contains(DUMMY_HOSTNAME))
            {
                Uri u = new Uri(url);

                if (!string.IsNullOrEmpty(u.UserInfo))
                {
                    if (u.UserInfo.IndexOf(":", StringComparison.Ordinal) >= 0)
                    {
                        username = u.UserInfo.Substring(0, u.UserInfo.IndexOf(":", StringComparison.Ordinal));
                        password = u.UserInfo.Substring(u.UserInfo.IndexOf(":", StringComparison.Ordinal) + 1);
                    }
                    else
                    {
                        username = u.UserInfo;
                    }
                }

                //We use the api.mosso.com hostname.
                //This allows the use of containers that have names that are not valid hostnames, 
                // such as container names with spaces in them
                if (u.Host.Equals(DUMMY_HOSTNAME))
                    m_path = Library.Utility.Uri.UrlDecode(u.PathAndQuery);
                else
                    m_path = u.Host + Library.Utility.Uri.UrlDecode(u.PathAndQuery);
            }
            else
            {
                m_path = uri.HostAndPath;
            }

            m_path = m_path.Trim('/');

            if (!options.TryGetValue("cloudfiles-authentication-url", out string authUrl))
                authUrl = Utility.Utility.ParseBoolOption(options, "cloudfiles-uk-account") ? AUTH_URL_UK : AUTH_URL_US;

            m_authClient = new HttpClient()
            {
                BaseAddress = new Uri(authUrl),
                DefaultRequestHeaders =
                {
                    { "X-Auth-User", username },
                    { "X-Auth-Key", password }
                }
            };
        }

        #region IBackend Members

        public string DisplayName => Strings.CloudFiles.DisplayName;

        public string Description => Strings.CloudFiles.Description_v2;

        public string ProtocolKey => "cloudfiles";

        public string[] DNSName => new string[] { m_authClient.BaseAddress?.Host, m_storageClient?.BaseAddress?.Host };

        public IEnumerable<IFileEntry> List()
        {
            EnsureStorageClient().GetAwaiter().GetResult();

            string extraUrl = $"?format=xml&limit={ITEM_LIST_LIMIT}";
            string markerUrl = "";

            bool repeat;

            do
            {
                using HttpResponseMessage resp = m_storageClient.GetAsync(extraUrl + markerUrl).Result;
                if (resp.StatusCode == HttpStatusCode.NotFound)
                {
                    if (markerUrl == "") //Only check on first iteration
                    {
                        throw new FolderMissingException();
                    }

                    // TODO-DNC: Better error message in this scenario?
                    throw new Exception("Unable to retreive results page.");
                }

                using Stream respStream = resp.Content.ReadAsStreamAsync().Result;
                var doc = new System.Xml.XmlDocument();
                doc.Load(respStream);

                System.Xml.XmlNodeList nodeList = doc.SelectNodes("container/object");

                //Perhaps the folder does not exist?
                //The response should be 404 from the server, but it is not :(
                if (nodeList.Count == 0 && markerUrl == "") //Only on first iteration
                {
                    try { CreateFolder(); }
                    catch { } //Ignore
                }

                string lastItemName = "";
                foreach (System.Xml.XmlNode node in nodeList)
                {
                    string name = node["name"].InnerText;

                    if (!long.TryParse(node["bytes"].InnerText, out long size))
                        size = -1;
                    if (!DateTime.TryParse(node["last_modified"].InnerText, out DateTime lastModified))
                        lastModified = new DateTime();

                    lastItemName = name;
                    yield return new FileEntry(name, size, lastModified, lastModified);
                }

                repeat = nodeList.Count == ITEM_LIST_LIMIT;
                markerUrl = "&marker=" + Library.Utility.Uri.UrlEncode(lastItemName);
            } 
            while (repeat);
        }

        public Task PutAsync(string remotename, string filename, CancellationToken cancelToken)
        {
            using FileStream fs = File.OpenRead(filename);
            return PutAsync(remotename, fs, cancelToken);
        }

        public void Get(string remotename, string filename)
        {
            GetAsync(remotename, filename).GetAwaiter().GetResult();
        }

        public async Task GetAsync(string remotename, string filename)
        {
            using FileStream fs = File.Create(filename);
            await GetAsync(remotename, fs);
        }

        public void Delete(string remotename)
        {
            DeleteAsync(remotename).GetAwaiter().GetResult();
        }

        public async Task DeleteAsync(string remotename)
        {
            await EnsureStorageClient();

            using HttpResponseMessage resp = await m_storageClient.DeleteAsync(remotename);

            if (resp.StatusCode == HttpStatusCode.NotFound)
                throw new FileMissingException();

            if (!resp.IsSuccessStatusCode)
                throw new Exception(Strings.CloudFiles.FileDeleteError);
        }

        public IList<ICommandLineArgument> SupportedCommands
        {
            get 
            {
                return new List<ICommandLineArgument>(new ICommandLineArgument[] {
                    new CommandLineArgument("auth-password", CommandLineArgument.ArgumentType.Password, Strings.CloudFiles.DescriptionAuthPasswordShort, Strings.CloudFiles.DescriptionAuthPasswordLong),
                    new CommandLineArgument("auth-username", CommandLineArgument.ArgumentType.String, Strings.CloudFiles.DescriptionAuthUsernameShort, Strings.CloudFiles.DescriptionAuthUsernameLong),
                    new CommandLineArgument("cloudfiles-username", CommandLineArgument.ArgumentType.String, Strings.CloudFiles.DescriptionUsernameShort, Strings.CloudFiles.DescriptionUsernameLong, null, new string[] {"auth-username"} ),
                    new CommandLineArgument("cloudfiles-accesskey", CommandLineArgument.ArgumentType.Password, Strings.CloudFiles.DescriptionPasswordShort, Strings.CloudFiles.DescriptionPasswordLong, null, new string[] {"auth-password"}),
                    new CommandLineArgument("cloudfiles-uk-account", CommandLineArgument.ArgumentType.Boolean, Strings.CloudFiles.DescriptionUKAccountShort, Strings.CloudFiles.DescriptionUKAccountLong("cloudfiles-authentication-url", AUTH_URL_UK)),
                    new CommandLineArgument("cloudfiles-authentication-url", CommandLineArgument.ArgumentType.String, Strings.CloudFiles.DescriptionAuthenticationURLShort, Strings.CloudFiles.DescriptionAuthenticationURLLong_v2("cloudfiles-uk-account"), AUTH_URL_US),
                });
            }
        }

        #endregion

        #region IBackend_v2 Members
        
        public void Test()
        {
            //The "Folder not found" is not detectable :(
            this.TestList();
        }

        public void CreateFolder()
        {
            CreateFolderAsync().GetAwaiter().GetResult();
        }

        public async Task CreateFolderAsync()
        {
            await EnsureStorageClient();

            using HttpResponseMessage resp = await m_storageClient.PutAsync("", new StringContent(string.Empty));
            resp.EnsureSuccessStatusCode();
        }

        #endregion

        #region IStreamingBackend Members

        public void Get(string remotename, System.IO.Stream stream)
        {
            GetAsync(remotename, stream).GetAwaiter().GetResult();
        }

        public async Task GetAsync(string remoteName, System.IO.Stream stream)
        {
            await EnsureStorageClient();

            HttpResponseMessage resp = await m_storageClient.GetAsync(remoteName);
            if(resp.StatusCode == HttpStatusCode.NotFound)
            {
                throw new Exception(Strings.CloudFiles.UnexpectedResponseError);
            }
            else if (!resp.IsSuccessStatusCode)
            {
                throw new Exception(Strings.CloudFiles.UnexpectedResponseError);
            }

            string md5Hash = resp.Headers.ETag?.Tag.Trim('"');

            using var mds = new Utility.MD5CalculatingStream(await resp.Content.ReadAsStreamAsync());
            Utility.Utility.CopyStream(mds, stream, true, m_copybuffer);

            if (!string.Equals(mds.GetFinalHashString(), md5Hash, StringComparison.OrdinalIgnoreCase))
                throw new Exception(Strings.CloudFiles.ETagVerificationError);
        }

        public async Task PutAsync(string remotename, System.IO.Stream stream, CancellationToken cancelToken)
        {
            await EnsureStorageClient();

            //If we can pre-calculate the MD5 hash before transmission, do so
            /*if (stream.CanSeek)
            {
                System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
                req.Headers["ETag"] = Core.Utility.ByteArrayAsHexString(md5.ComputeHash(stream)).ToLower(System.Globalization.CultureInfo.InvariantCulture);
                stream.Seek(0, System.IO.SeekOrigin.Begin);

                using (System.IO.Stream s = req.GetRequestStream())
                    Core.Utility.CopyStream(stream, s);

                //Reset the timeout to the default value of 100 seconds to 
                // avoid blocking the GetResponse() call
                req.Timeout = 100000;

                //The server handles the eTag verification for us, and gives an error if the hash was a mismatch
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                    if ((int)resp.StatusCode >= 300)
                        throw new WebException(Strings.CloudFiles.FileUploadError, null, WebExceptionStatus.ProtocolError, resp);

            }
            else //Otherwise use a client-side calculation
            */
            //TODO: We cannot use the local MD5 calculation, because that could involve a throttled read,
            // and may invoke various events
            {
                using var hashStream = new Utility.MD5CalculatingStream(stream);
                var content = new StreamContent(hashStream)
                {
                    Headers =
                    {
                        ContentType = new MediaTypeHeaderValue("application/octet-stream")
                    }
                };
                var resp = await m_storageClient.PutAsync(remotename, content, cancelToken);

                if (resp.StatusCode == HttpStatusCode.NotFound)
                {
                    throw new FolderMissingException();
                }

                if (resp.StatusCode >= (HttpStatusCode)300)
                {
                    throw new Exception(Strings.CloudFiles.FileUploadError);
                }

                string expectedHash = resp.Headers.ETag?.Tag.Trim('"');
                string actualHash = hashStream.GetFinalHashString();
                if (expectedHash == null || !string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
                {
                    //Remove the broken file
                    try { await DeleteAsync(remotename); }
                    catch { }

                    throw new Exception(Strings.CloudFiles.ETagVerificationError);
                }
            }
        }

        #endregion

        private async Task EnsureStorageClient()
        {
            // If we have a client and create one if needed
            if (m_storageClient != null)
            {
                return;
            }
             
            using HttpResponseMessage resp = await m_authClient.GetAsync("");
            if (!resp.IsSuccessStatusCode)
                throw new Exception(Strings.CloudFiles.UnexpectedResponseError);

            string storageUrl = resp.Headers.GetValues("X-Storage-Url").FirstOrDefault();
            string authToken = resp.Headers.GetValues("X-Auth-Token").FirstOrDefault();

            if (string.IsNullOrEmpty(authToken) || string.IsNullOrEmpty(storageUrl))
                throw new Exception(Strings.CloudFiles.UnexpectedResponseError);

            m_storageClient = new HttpClient(new HttpClientHandler { PreAuthenticate = true })
            {
                BaseAddress = new Uri(storageUrl + m_path + "/"),
            };

            m_storageClient.DefaultRequestHeaders.Add("X-Auth-Token", Utility.Uri.UrlPathEncode(authToken).Replace("%2f", "/"));
            string backendVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
            m_storageClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DuplicatiCloudFilesBackend", backendVersion));
        }

        #region IDisposable Members

        public void Dispose()
        {
        }

        #endregion
    }
}

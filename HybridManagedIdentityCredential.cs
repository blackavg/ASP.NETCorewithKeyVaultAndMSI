using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Core;
using System.Threading;
using System.Net.Http;
using System.IO;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Net;

namespace ASPCoreWithKV
{
    public class HybridManagedIdentityCredential : TokenCredential
    {
        // http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=<resource>
        // header Authorization: get-content (C:\ProgramData\AzureConnectedMachineAgent\Tokens\*.key)
        // windows: C:\ProgramData\AzureConnectedMachineAgent\Tokens\*.key
        // linux: ... ?
        private readonly HttpClient _client;
        private readonly Dictionary<string, AccessToken> _tokens;
        public HybridManagedIdentityCredential() : this(new HttpClient()) { }
        public HybridManagedIdentityCredential(IHttpClientFactory clientFactory) : this(clientFactory.CreateClient()) { }
        public HybridManagedIdentityCredential(HttpClient client)
        {
            _client = client;
            // metadata header required for IMDS endpoint
            _client.DefaultRequestHeaders.TryAddWithoutValidation("Metadata", "true");
            // a (too-simple) token cache - I think Azure.Identity handles some of its own caching anyway so wouldn't expect this to get called frequently
            _tokens = new Dictionary<string, AccessToken>();
        }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return GetAccessTokenAsync(requestContext.Scopes).Result;
        }

        public async override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return await GetAccessTokenAsync(requestContext.Scopes);
        }

        private async Task<AccessToken> GetAccessTokenAsync(string[] scopes)
        {
            var resource = ScopeUtils.ScopesToResource(scopes);
            if (_tokens.ContainsKey(resource) && _tokens.TryGetValue(resource, out var token))
            {
                if (token.ExpiresOn > DateTime.UtcNow)
                {
                    return token;
                }
                _tokens.Remove(resource);
            }

            _tokens.TryAdd(resource, await GetAccessTokenFromEndpoint(resource));
            return await GetAccessTokenAsync(scopes);
        }

        private async Task<AccessToken> GetAccessTokenFromEndpoint(string resource)
        {
            var url = new Uri($"http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource={resource}");
            Console.WriteLine($"Getting token from: {url} for resource: {resource}");

            var response = await _client.GetAsync(url);
            if (!response.IsSuccessStatusCode && response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var wwwAuthHeader = response.Headers.WwwAuthenticate.ToString();
                var filePath = wwwAuthHeader.Split(' ')[1].Split('=')[1];
                Console.WriteLine($"Getting token data from path: {filePath}");

                if (string.IsNullOrWhiteSpace(filePath)) { throw new Exception("no file"); }
                var tokenFileData = await File.ReadAllTextAsync(filePath);
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", tokenFileData);

                var authResponse = await _client.GetAsync(url);
                var receivedToken = JsonSerializer.Deserialize<MsiTokenResponse>(await authResponse.Content.ReadAsStringAsync()); // stream?
                var tokenExpiresOn = DateTimeOffset.FromUnixTimeSeconds(long.Parse(receivedToken.ExpiresOn));
                return new AccessToken(receivedToken.AccessToken, tokenExpiresOn);
            }
            Console.WriteLine(await response.Content.ReadAsStringAsync());
            return default;
        }
    }

    // see: https://github.com/azure-sdk/azure-sdk-for-net/blob/master/sdk/identity/Azure.Identity/src/ScopeUtilities.cs
    public class ScopeUtils
    {
        private const string DefaultSuffix = "/.default";
        public static string ScopesToResource(string[] scopes)
        {
            if (scopes == null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            if (scopes.Length != 1)
            {
                throw new ArgumentException("To convert to a resource string the specified array must be exactly length 1", nameof(scopes));
            }

            if (!scopes[0].EndsWith(DefaultSuffix, StringComparison.Ordinal))
            {
                return scopes[0];
            }

            return scopes[0].Remove(scopes[0].LastIndexOf(DefaultSuffix, StringComparison.Ordinal));
        }
    }
    public class MsiTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonPropertyName("expires_in")]
        public string ExpiresIn { get; set; }

        [JsonPropertyName("expires_on")]
        public string ExpiresOn { get; set; }

        [JsonPropertyName("not_before")]
        public string NotBefore { get; set; }

        [JsonPropertyName("resource")]
        public string Resource { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Formats.Asn1.AsnWriter;

namespace MAUIMACAuth.Services;
public interface IAuthenticationService
{
    //Task<string> Logout(string userName);
    //Task<IEnumerable<IAccount>> GetExistingAccountsAsync();
    Task<string> GetTokenAsync(string userName, string[] scopes, bool silentOnly);
}

public static class AuthCacheConfig
{
    // App settings
    public static readonly string[] Scopes = new[] { "040a74c6-5df7-485c-9133-9d5d4c953717/API.Access" };
    public const string Authority = "https://login.microsoftonline.com/common";
    public const string ClientId = "91e2b896-1ef4-4c2e-bd36-e3374926ed77";
    public const string RedirectURI = "mauimac://callback";
}

public class AuthenticationService : IAuthenticationService
{
    
    public async Task<string> GetTokenAsync(string userName, string[] scopes, bool silentOnly)
    {
        try
        {
            WebAuthenticatorResult result = await WebAuthenticator.AuthenticateAsync(
            new Uri(GenerateCodeUri(scopes)), new Uri(AuthCacheConfig.RedirectURI));
            var code = result.Properties["code"];

            return string.Empty;
        }
        catch(Exception ex)
        {
            return string.Empty;
        }
    }

    private async Task GetTokenFromAzAsync(string code)
    {
        var loginPayload = new List<KeyValuePair<string, string>>();
        
    }

    private string GenerateCodeUri(string[] scopes)
    {
        return AuthCacheConfig.Authority.TrimEnd('/') +
            $"/oauth2/v2.0/authorize?client_id={AuthCacheConfig.ClientId}&scope=" +
            string.Join(" ", scopes) + 
            $"&redirect_uri={AuthCacheConfig.RedirectURI}" +
            $"&response_type=code" +
            $"&prompt=login";
    }

}
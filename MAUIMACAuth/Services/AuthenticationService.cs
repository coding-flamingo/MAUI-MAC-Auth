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
    public static readonly string[] Scopes = new[] { "68554b48-233f-42b4-9aa7-2eadca4d7727//API.Access" };
    public const string Authority = "https://login.microsoftonline.com/common";
    public const string ClientId = "eddb4ead-89dd-4da8-9196-09c7ea82d724";
    public const string RedirectURI = "http://localhost:6969";
}

public class AuthenticationService : IAuthenticationService
{
    
    public async Task<string> GetTokenAsync(string userName, string[] scopes, bool silentOnly)
    {
        WebAuthenticatorResult result = await WebAuthenticator.AuthenticateAsync(
            new Uri(GenerateCodeUri(scopes)), new Uri(AuthCacheConfig.RedirectURI));
        //todo check what happens when it is just closed
        return result.RefreshToken;

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
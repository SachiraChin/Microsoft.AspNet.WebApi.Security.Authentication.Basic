using System;

namespace Microsoft.AspNet.WebApi.Security.Authentication.Basic
{
    public interface IUserAuthenticationService : IDisposable
    {
        int Authenticate(string userName, string password);
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http.Controllers;

namespace Microsoft.AspNet.WebApi.Security.Authentication.Basic
{
    public static class Extensions
    {
        public static BasicAuthenticationIdentity GetIdentity(this HttpActionContext context)
        {
            string authHeaderValue = null;
            var authRequest = context.Request.Headers.Authorization;
            if (!string.IsNullOrEmpty(authRequest?.Scheme) && authRequest.Scheme == "Basic")
                authHeaderValue = authRequest.Parameter;

            return string.IsNullOrEmpty(authHeaderValue) ? null : authHeaderValue.GetIdentity();
        }

        public static BasicAuthenticationIdentity GetIdentity(this string authString)
        {
            var authHeaderValue = Encoding.Default.GetString(Convert.FromBase64String(authString));
            var credentials = authHeaderValue.Split(':');
            return credentials.Length < 2 ? null : new BasicAuthenticationIdentity(credentials[0], credentials[1]);
        }
    }
}

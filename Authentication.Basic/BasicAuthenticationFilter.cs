using System.Security;
using System.Threading;
using System.Web.Http.Controllers;

namespace Microsoft.AspNet.WebApi.Security.Authentication.Basic
{
    /// <summary>
    /// Custom Authentication Filter Extending basic Authentication
    /// </summary>
    public class BasicAuthenticationFilter : GenericAuthenticationFilter
    {
        private readonly IUserAuthenticationService _authenticationService;
        /// <summary>
        /// Default Authentication Constructor
        /// </summary>
        public BasicAuthenticationFilter(IUserAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        /// <summary>
        /// AuthenticationFilter constructor with isActive parameter
        /// </summary>
        /// <param name="isActive"></param>
        /// <param name="authenticationService"></param>
        public BasicAuthenticationFilter(bool isActive, IUserAuthenticationService authenticationService)
            : base(isActive)
        {
            _authenticationService = authenticationService;
        }

        /// <summary>
        /// Protected overridden method for authorizing user
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="actionContext"></param>
        /// <returns></returns>
        /// <exception cref="SecurityException">The caller does not have the permission required to set the principal. </exception>
        protected override bool OnAuthorizeUser(string username, string password, HttpActionContext actionContext)
        {
            var userId = _authenticationService.Authenticate(username, password);
            if (userId <= 0) return false;

            var basicAuthenticationIdentity = Thread.CurrentPrincipal.Identity as BasicAuthenticationIdentity;
            if (basicAuthenticationIdentity != null)
                basicAuthenticationIdentity.UserId = userId;
            return true;
        }
    }
}

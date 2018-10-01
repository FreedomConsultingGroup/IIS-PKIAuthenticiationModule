using System;
using System.Security.Principal;
using System.Web;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;
using System.Security;
using System.IO;

namespace FCG.PKIAuthentication
{
    public class PkiAuthModule : IHttpModule
    {
        public void Init(HttpApplication context)
        {
            /* On startup, bind the AuthenticateRequestHandler function to the AuthenticateRequest
             * event that is called during the Authentication layer of IIS.
             * Then, create the log file for the current startup time*/
            context.AuthenticateRequest += new EventHandler(AuthenticateRequestHandler);
            Global.LogInfo("Method: FCG.PKIAuthentication.PkiAuth.AuthenticateRequestHandler bound to AuthenticateRequest Event");
        }


        public void Dispose()
        {
        }

        private void AuthenticateRequestHandler(object sender, EventArgs e)
        {
            /* The main function of the module. Called by the AuthenticateRequest event. Handles request and
             * attaches username to the Identity of the request 
             */
            // Pull the context from the request
            HttpApplication app = (HttpApplication)sender;
            HttpContext context = app.Context;

            // Log information about the request
            Global.LogInfo("Request received. " +
                Environment.NewLine + "\tURL: " + context.Request.Url +
                Environment.NewLine + "\tReferrer: " + context.Request.UrlReferrer +
                Environment.NewLine + "\tAgent: " + context.Request.UserAgent +
                Environment.NewLine + "\tIP: " + context.Request.UserHostAddress);

            String username = "";

            // Check for client certificate
            if (context.Request.ClientCertificate.IsPresent)
            {
                // Authenticate certificate
                if (IsAuthenticated(context.Request.ClientCertificate, ref username))
                {
                    context.User = new GenericPrincipal(new GenericIdentity(username), null);
                    Global.LogInfo("\tUser: " + username + " properly authenticated");
                    // alternatively, context.User = new GenericPrincipal(new GenericIdentity(email), null);
                }
                else
                {
                    Global.LogInfo("\tUnable to authenticate certificate");
                    throw new HttpException(403, "Forbidden");
                }
            }
            else
            {
                Global.LogInfo("\tCertificate not found");
                throw new HttpException(403, "Forbidden");
            }
        }

        public bool IsAuthenticated(HttpClientCertificate httpClientCertificate, ref string username)
        {
            // Explicitly cast certificate to usable type, X509Certificate2
            var certificate = new X509Certificate2(httpClientCertificate.Certificate);
            string cName = "";
            // Verify the certificate, then if it is create the username and bind it to the reference
            if (Verify(certificate, ref cName))
            {
                string[] name = cName.Trim().Split(' ');
                if(name.Length == 1)
                {
                    username = name[0];
                }
                else if (name.Length > 0)
                {
                    // max specifies the maximum length of the username generated
                    int max = 10;
                    for(int i = 0; i < name.Length; i++)
                    {
                        int remaining = max - username.Length;
                        if (remaining < 0)
                        {
                            break;
                        }
                        else
                        {
                            for (int j = 0; j < remaining; j++)
                            {
                                if (j < name[i].Length)
                                {
                                    username += name[i][j];
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                    Global.LogInfo("\tUsername: \"" + username + "\" found. Logging in...");
                }
                else
                {
                    Global.LogInfo("\tCertificate does not have a Common Name (CN), unable to create username");
                    return false;
                }
                return true;
            }
            else
            {
                Global.LogInfo("\tUnable to verify certificate");
                return false;
            }
        }


        private bool Verify(X509Certificate2 certificate, ref string cName)
        {
            /* This function currently checks to see if the certificate is signed by the specific trusted root that is used to create new users,
               then checks to see if the certificate subject contains a common name.
               IIS checks the certificate against the Trusted Root certificate store before the AuthenticateRequest event is called,
               so there is no need to do that here. */
            if (certificate == null)
            {
                Global.LogInfo("\tCertificate not found");
                return false;
            }

            X509Certificate2 root = new X509Certificate2();
            SecureString passwd = new SecureString();
            Array.ForEach(File.ReadAllText(Environment.GetEnvironmentVariable("CA_USER_AUTHORITY_PASSWD")).ToCharArray(), b => passwd.AppendChar(b));
            root.Import(Environment.GetEnvironmentVariable("CA_USER_AUTHORITY"), passwd, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

            // TODO https://stackoverflow.com/questions/6497040/how-do-i-validate-that-a-certificate-was-created-by-a-particular-certification-a

            string subject = certificate.Subject;
            string userPattern = @"CN=(?<cn>[^,]+)";
            Match match = Regex.Match(subject, userPattern, RegexOptions.None);
            if (match.Success)
            {
                cName = match.Groups["cn"].Value;
                return true;
            }
            Global.LogInfo("\tCommon Name not found. Unable to attach username to request with given certificate");
            return false;
        }
    }
}
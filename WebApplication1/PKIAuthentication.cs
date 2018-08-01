using System;
using System.Security.Principal;
using System.Web;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

namespace PKI.Authentication.Module
{
    public class PkiAuthModule : IHttpModule
    {
        #region IHttpModule Members
        private String logPath = @"C:\inetpub\logs\PKIAuth\";
        public void Init(HttpApplication context)
        {
            /* On startup, bind the AuthenticateRequestHandler function to the AuthenticateRequest
             * event that is called during the Authentication layer of IIS.
             * Then, create the log file for the current startup time*/
            context.AuthenticateRequest += new EventHandler(AuthenticateRequestHandler);
            System.DateTime dateTime = System.DateTime.Now;
            logPath += dateTime.Day.ToString() + "_" + dateTime.Month.ToString() + "_" + dateTime.Year.ToString() + "-" + dateTime.Hour + "-" + dateTime.Minute + "-" + dateTime.Second + "-" + dateTime.Millisecond + "_Log.txt";
            File.AppendAllText(logPath, System.DateTime.Now + ": AuthenticateRequest Event bound" + Environment.NewLine);
        }


        public void Dispose()
        {
        }

        #endregion

        private void AuthenticateRequestHandler(object sender, EventArgs e)
        {
            /* The main function of the module. Called by the AuthenticateRequest event. Handles request and
             * attaches username to the Identity of the request 
             */
            // Pull the context from the request
            var app = (HttpApplication)sender;
            HttpContext context = app.Context;

            // Log information about the request
            File.AppendAllText(logPath, "\tRequest received. " +
                Environment.NewLine + "\t\tURL: " + context.Request.Url +
                Environment.NewLine + "\t\tReferrer: " + context.Request.UrlReferrer +
                Environment.NewLine + "\t\tAgent: " + context.Request.UserAgent +
                Environment.NewLine + "\t\tIP: " + context.Request.UserHostAddress + Environment.NewLine);

            String username = "";

            // Check for client certificate
            if (context.Request.ClientCertificate.IsPresent)
            {
                // Authenticate certificate
                if (IsAuthenticated(context.Request.ClientCertificate, ref username))
                {
                    context.User = new GenericPrincipal(new GenericIdentity(username), null);
                    File.AppendAllText(logPath, "\tUser: " + username + " properly authenticated" + Environment.NewLine);
                    // alternatively, context.User = new GenericPrincipal(new GenericIdentity(email), null);
                }
                else
                {
                    File.AppendAllText(logPath, "\tUnable to authenticate certificate" + Environment.NewLine);
                    throw new HttpException(403, "Forbidden");
                }
            }
            else
            {
                File.AppendAllText(logPath, "\tCertificate not found" + Environment.NewLine);
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
                    File.AppendAllText(logPath, "\tUsername: \"" + username + "\" found. Logging in..." + Environment.NewLine);
                }
                else
                {
                    File.AppendAllText(logPath, "\tCertificate does not have a Common Name (CN), unable to create username" + Environment.NewLine);
                    return false;
                }
                return true;
            }
            else
            {
                File.AppendAllText(logPath, "\tUnable to verify certificate in IsAuthenticated()" + Environment.NewLine);
                return false;
            }
        }


        private bool Verify(X509Certificate2 certificate, ref string cName)
        {
            /* This function currently only checks to see if the certificate subject contains a common name.
               IIS checks the certificate against the Trusted Root certificate store before the AuthenticateRequest event is called,
               so there is no need to do that here. In the future, 3rd party verification will be called here
               to check if the certificate is valid. */
            if (certificate == null)
            {
                File.AppendAllText(logPath, "\tCertificate not found in Verify()" + Environment.NewLine);
                return false;
            }
            string subject = certificate.Subject;
            //string emailPattern = @"(?(DEFINE)
            // (?<addr_spec> (?&local_part) @ (?&domain) )
            // (?<local_part> (?&dot_atom) | (?&quoted_string) | (?&obs_local_part) )
            // (?<domain> (?&dot_atom) | (?&domain_literal) | (?&obs_domain) )
            // (?<domain_literal> (?&CFWS)? \[ (?: (?&FWS)? (?&dtext) )* (?&FWS)? \] (?&CFWS)? )
            // (?<dtext> [\x21-\x5a] | [\x5e-\x7e] | (?&obs_dtext) )
            // (?<quoted_pair> \\ (?: (?&VCHAR) | (?&WSP) ) | (?&obs_qp) )
            // (?<dot_atom> (?&CFWS)? (?&dot_atom_text) (?&CFWS)? )
            // (?<dot_atom_text> (?&atext) (?: \. (?&atext) )* )
            // (?<atext> [a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+ )
            // (?<atom> (?&CFWS)? (?&atext) (?&CFWS)? )
            // (?<word> (?&atom) | (?&quoted_string) )
            // (?<quoted_string> (?&CFWS)? "" (?: (?&FWS)? (?&qcontent) )* (?&FWS)? "" (?&CFWS)? )
            // (?<qcontent> (?&qtext) | (?&quoted_pair) )
            // (?<qtext> \x21 | [\x23-\x5b] | [\x5d-\x7e] | (?&obs_qtext) )
            // # comments and whitespace
            // (?<FWS> (?: (?&WSP)* \n )? (?&WSP)+ | (?&obs_FWS) )
            // (?<CFWS> (?: (?&FWS)? (?&comment) )+ (?&FWS)? | (?&FWS) )
            // (?<comment> \( (?: (?&FWS)? (?&ccontent) )* (?&FWS)? \) )
            // (?<ccontent> (?&ctext) | (?&quoted_pair) | (?&comment) )
            // (?<ctext> [\x21-\x27] | [\x2a-\x5b] | [\x5d-\x7e] | (?&obs_ctext) )
            // # obsolete tokens
            // (?<obs_domain> (?&atom) (?: \. (?&atom) )* )
            // (?<obs_local_part> (?&word) (?: \. (?&word) )* )
            // (?<obs_dtext> (?&obs_NO_WS_CTL) | (?&quoted_pair) )
            // (?<obs_qp> \\ (?: \x00 | (?&obs_NO_WS_CTL) | \n |  ) )
            // (?<obs_FWS> (?&WSP)+ (?: \n (?&WSP)+ )* )
            // (?<obs_ctext> (?&obs_NO_WS_CTL) )
            // (?<obs_qtext> (?&obs_NO_WS_CTL) )
            // (?<obs_NO_WS_CTL> [\x01-\x08] | \x0b | \x0c | [\x0e-\x1f] | \x7f )
            // # character class definitions
            // (?<VCHAR> [\x21-\x7E] )
            // (?<WSP> [ \t] )
            //)
            //^(?&addr_spec)$";
            string userPattern = @"CN=(?<cn>[^,]+)";
            Match match = Regex.Match(subject, userPattern, RegexOptions.None);
            if (match.Success)
            {
                cName = match.Groups["cn"].Value;
                return true;
            }
            File.AppendAllText(logPath, "\tCN match not found" + Environment.NewLine);
            return false;
        }
    }
}
using Microsoft.IdentityServer.Web.Authentication.External;
using System.Diagnostics;

namespace privacyIDEAADFSProvider
{
    internal class AdapterPresentationForm : IAdapterPresentationForm
    {
        public ADFSinterface[] inter;
        private IAuthenticationContext authContext = null;
        private bool error = false;
        
        public AdapterPresentationForm(bool error, ADFSinterface[] adfsinter)
        {
            this.error = error;
            inter = adfsinter;
        }

        public AdapterPresentationForm(ADFSinterface[] adfsinter, IAuthenticationContext authContext)
        {
            inter = adfsinter;
            this.authContext = authContext;
        }

        /// Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        /// to the cient.
        public string GetFormHtml(int lcid)
        {
#if DEBUG
            Debug.WriteLine($"{Helper.debugPrefix} GetFormHtml({lcid}), authContext isNull {authContext == null})");
#endif

            // check the localization with the lcid
            string errormessage = "";
            string welcomemessage = "";
            string htmlTemplate = Resources.AuthPage;

            if (inter != null)
            {
                foreach (ADFSinterface adfsui in inter)
                {
                    if (adfsui.LICD == lcid.ToString())
                    {
                        errormessage = error ? adfsui.errormessage : "";
                        welcomemessage = adfsui.wellcomemessage;
                    }
                    // fallback to EN-US if nothing is defined
                    else
                    {
                        errormessage = error ? "Login failed! Please try again!" : "";
                        welcomemessage = "Please provide the One Time Password:";
                    }
                }
            }
            if (!error)
            {
                if ((authContext != null) && (authContext.Data.ContainsKey("qrcode")))
                {
                    errormessage = "You have not registered a One Time Password yet. Please scan the QR code below with a mobile app (Google Authenticator, Microsoft Authenticator, Authy, etc) to register for OTP.";
                    htmlTemplate = htmlTemplate.Replace("<!--#QRCODE-->", string.Format("<img style=\"max-width: 100%\" src=\"{0}\" />", authContext.Data["qrcode"]));
                }
            }
            htmlTemplate = htmlTemplate.Replace("#MESSAGE#", welcomemessage);
            htmlTemplate = htmlTemplate.Replace("#ERROR#", errormessage);

            return htmlTemplate;
        }

        /// Return any external resources, ie references to libraries etc., that should be included in 
        /// the HEAD section of the presentation form html. 
        public string GetFormPreRenderHtml(int lcid)
        {
#if DEBUG
            Debug.WriteLine($"{Helper.debugPrefix} GetFormPreRenderHtml({lcid})");
#endif
            return null;
        }

        //returns the title string for the web page which presents the HTML form content to the end user
        public string GetPageTitle(int lcid)
        {
#if DEBUG
            Debug.WriteLine($"{Helper.debugPrefix} GetFormPreRenderHtml({lcid})");
#endif
            return "privacyIDEA MFA Provider for ADFS";
        }

    }
}

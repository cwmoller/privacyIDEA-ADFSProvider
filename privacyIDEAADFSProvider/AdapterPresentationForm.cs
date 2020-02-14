using Microsoft.IdentityServer.Web.Authentication.External;
using System.Diagnostics;
using System.Globalization;

namespace privacyIDEAADFSProvider
{
    internal class AdapterPresentationForm : IAdapterPresentationForm
    {
        public ADFSinterface[] inter;
        private IAuthenticationContext AuthContext { get; set; }
        private bool Error { get; set; }
        
        public AdapterPresentationForm(bool error, ADFSinterface[] adfsinter)
        {
            this.Error = error;
            inter = adfsinter;
        }

        public AdapterPresentationForm(ADFSinterface[] adfsinter, IAuthenticationContext authContext)
        {
            inter = adfsinter;
            this.AuthContext = authContext;
        }


        /// Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        /// to the cient.
        public string GetFormHtml(int lcid)
        {
#if DEBUG
            Debug.WriteLine($"{Helper.debugPrefix} GetFormHtml({lcid}), AuthContext isNull {AuthContext == null})");
#endif

            // check the localization with the lcid
            string errormessage = "";
            string welcomemessage = "";
            string htmlTemplate = Resources.AuthPage;

            if (inter != null)
            {
                foreach (ADFSinterface adfsui in inter)
                {
                    if (int.Parse(adfsui.LICD, new CultureInfo(lcid)) == lcid)
                    {
                        errormessage = Error ? adfsui.errormessage : "";
                        welcomemessage = adfsui.wellcomemessage;
                    }
                    // fallback to EN-US if nothing is defined
                    else
                    {
                        errormessage = Error ? "Login failed! Please try again!" : "";
                        welcomemessage = "Please provide the One Time Password:";
                    }
                }
            }
            if (!Error)
            {
                if ((AuthContext != null) && (AuthContext.Data.ContainsKey("qrcode")))
                {
                    errormessage = "You have not registered a One Time Password yet. Please scan the QR code below with a mobile app (Google Authenticator, Microsoft Authenticator, Authy, etc) to register for OTP.";
                    htmlTemplate = htmlTemplate.Replace("<!--#QRCODE-->", string.Format(new CultureInfo(lcid), "<img style=\"max-width: 100%\" src=\"{0}\" />", AuthContext.Data["qrcode"]));
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

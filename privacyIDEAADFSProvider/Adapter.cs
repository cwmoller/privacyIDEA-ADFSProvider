using System.Net;
using Microsoft.IdentityServer.Web.Authentication.External;
using Claim = System.Security.Claims.Claim;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Xml.Serialization;
using System.Collections.Generic;
using System;

namespace privacyIDEAADFSProvider
{
    public class Adapter : IAuthenticationAdapter
    {
        private string privacyIDEAurl = "";
        private string privacyIDEArealm = "";
        private string transaction_id = "";
        private bool ssl = true;
        private string token = "";
        private string admin_user = "";
        private string admin_pw = "";
        private ADFSinterface[] uidefinition;
        private OTPprovider otp_prov = null;

        public IAuthenticationAdapterMetadata Metadata
        {
            get { return new AdapterMetadata(); }
        }
        /// <summary>
        /// Initiates a new authentication process and returns to the ADFS system.
        /// </summary>
        /// <param name="identityClaim">Claim information from the ADFS</param>
        /// <param name="request">The HTTP request</param>
        /// <param name="authContext">The context for the authentication</param>
        /// <returns>new instance of IAdapterPresentationForm</returns>
        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext authContext)
        {
#if DEBUG
            Debug.WriteLine($"{Helper.debugPrefix} BeginAuthentication() claim value {identityClaim.Value}");
#endif
            // check whether SSL validation is disabled in the config
            if (!ssl) ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;

            // trigger challenge
            otp_prov = new OTPprovider(privacyIDEAurl);
            // get a new admin token for all requests if an admin password is defined
            if (!string.IsNullOrEmpty(admin_pw) && !string.IsNullOrEmpty(admin_user))
            {
                token = otp_prov.getAuthToken(admin_user, admin_pw);
                // trigger a challenge (SMS, Mail ...) for the the user
                if (otp_prov.hasToken(identityClaim.Value, privacyIDEArealm, token))
                {
                    transaction_id = otp_prov.triggerChallenge(identityClaim.Value, privacyIDEArealm, token);
                    authContext.Data.Add("transaction_id", transaction_id);
                }
                else
                {
                    // register a token, get QR code
                    Dictionary <string, string> QR = otp_prov.enrollTOTPToken(identityClaim.Value, privacyIDEArealm, token);
#if DEBUG
                    Debug.WriteLine($"{Helper.debugPrefix} BeginAuthentication() QR {Helper.ToDebugString(QR)}");
#endif
                    if (QR.ContainsKey("googleurl"))
                    {
                        authContext.Data.Add("qrcode", QR["googleurl"]);
                    }
                }
            }
            authContext.Data.Add("userid", identityClaim.Value);
            authContext.Data.Add("realm", privacyIDEArealm);

            return new AdapterPresentationForm(uidefinition, authContext);
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext authContext)
        {
            return true;
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            //this is where AD FS passes us the config data, if such data was supplied at registration of the adapter
            if ((configData != null) && (configData.Data != null))
            {
                try
                {
                    // load the config file
                    using (StreamReader reader = new StreamReader(configData.Data, Encoding.UTF8))
                    {
                        XmlRootAttribute xRoot = new XmlRootAttribute
                        {
                            ElementName = "server",
                            IsNullable = true
                        };
                        XmlSerializer serializer = new XmlSerializer(typeof(ADFSserver), xRoot);
                        ADFSserver server_config = (ADFSserver)serializer.Deserialize(reader);
                        admin_pw = server_config.adminpw;
                        admin_user = server_config.adminuser;
                        ssl = server_config.ssl.ToLower() == "true";
                        privacyIDEArealm = server_config.realm;
                        privacyIDEAurl = server_config.url;
                        uidefinition = server_config.@interface;
                    }
                }
                catch (Exception ex)
                {
#if DEBUG
                    Debug.WriteLine($"{Helper.debugPrefix} OnAuthenticationPipelineLoad() exception: {ex.Message}");
#endif
                    Helper.LogEvent($"OnAuthenticationPipelineLoad() exception: {ex.Message}", EventLogEntryType.Error);
                }
            }
        }
        /// <summary>
        /// cleanup function - nothing to do here
        /// </summary>
        public void OnAuthenticationPipelineUnload()
        {
        }
        /// <summary>
        /// Called on error and represents the authform with a error message
        /// </summary>
        /// <param name="request">the HTTP request object</param>
        /// <param name="ex">exception message</param>
        /// <returns>new instance of IAdapterPresentationForm derived class</returns>
        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            return new AdapterPresentationForm(true, uidefinition);
        }
        /// <summary>
        /// Function call after the user hits submit - it proofs the values (OTP pin)
        /// </summary>
        /// <param name="authContext"></param>
        /// <param name="proofData"></param>
        /// <param name="request"></param>
        /// <param name="outgoingClaims"></param>
        /// <returns></returns>
        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext authContext, IProofData proofData, HttpListenerRequest request, out Claim[] outgoingClaims)
        {
#if DEBUG
            Debug.WriteLine($"{Helper.debugPrefix} TryEndAuthentication()");
#endif
            outgoingClaims = new Claim[0];
            if (ValidateProofData(proofData, authContext))
            {
                //authn complete - return authn method
                outgoingClaims = new[]
                {
                     // Return the required authentication method claim, indicating the particulate authentication method used.
                     new Claim( "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "http://schemas.microsoft.com/ws/2012/12/authmethod/otp")
                };
                return null;
            }
            else
            {
                //authentication not complete - return new instance of IAdapterPresentationForm derived class and the generic error message
                return new AdapterPresentationForm(true, uidefinition);
            }
        }

        /// <summary>
        /// Check the OTP and do the real authentication
        /// </summary>
        /// <param name="proofData">the data from the HTML field</param>
        /// <param name="authContext">The auth context which contains secured parametes</param>
        /// <returns>True if auth is done and user can be validated</returns>
        private bool ValidateProofData(IProofData proofData, IAuthenticationContext authContext)
        {
            if (proofData == null || proofData.Properties == null || !proofData.Properties.ContainsKey("otpvalue"))
            {
                throw new ExternalAuthenticationException($"ValidateProofData() OTP not found", authContext);
            }

            if (!ssl)
            {
                ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            }

            try
            {
                string otpvalue = (string)proofData.Properties["otpvalue"];
                string session_user = (string)authContext.Data["userid"];
                string session_realm = (string)authContext.Data["realm"];
                string transaction_id = authContext.Data.ContainsKey("transaction_id") ? (string)authContext.Data["transaction_id"] : "";
#if DEBUG
                Debug.WriteLine($"{Helper.debugPrefix} ValidateProofData() user {session_user}, OTP {otpvalue}, realm {session_realm}, transaction {transaction_id}");
#endif
                // if we're running a server farm and BeginAuthentication was called on a different server
                if (otp_prov is null)
                {
                    otp_prov = new OTPprovider(privacyIDEAurl);
                }
                return otp_prov.validateOTP(session_user, otpvalue, session_realm, transaction_id);
            }
            catch (Exception ex)
            {
#if DEBUG
                Debug.WriteLine($"{Helper.debugPrefix} ValidateProofData() exception: {ex.Message}");
#endif
                throw new ExternalAuthenticationException($"ValidateProofData() exception: {ex.Message}", authContext);
            }
        }

    }
}

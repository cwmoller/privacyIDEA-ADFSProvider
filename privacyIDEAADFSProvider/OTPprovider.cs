using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Runtime.Serialization.Json;
using System.Xml;
using System.Xml.Linq;
using static privacyIDEAADFSProvider.Helper;

namespace privacyIDEAADFSProvider
{
    public class OTPprovider
    {
        private string URL;
        /// <summary>
        /// Class creates a OTPprovide for the privacyIDEA system
        /// </summary>
        /// <param name="privacyIDEAurl">Provide the URL (HTTPS) to the privacyIDEA system</param>
        public OTPprovider(string privacyIDEAurl)
        {
            URL = privacyIDEAurl;
        }
        /// <summary>
        /// Dispatcher methode for #14 - made two request to avoid auth fail by TOTP with PIN
        /// </summary>
        /// <param name="OTPuser">User name for the token</param>
        /// <param name="OTPpin">PIN for validation</param>
        /// <param name="realm">Domain/realm name</param>
        /// <param name="transaction_id">ID for the coresponding challenge</param>
        /// <returns>true if the pin is correct</returns>
        public bool getAuthOTP(string OTPuser, string OTPpin, string realm, string transaction_id)
        {
#if DEBUG
            Debug.WriteLine(String.Format("{0} getAuthOTP({1}, {2}, {3}, {4})", Adapter.debugPrefix, OTPuser, OTPpin, realm, transaction_id));
#endif
            // first request with transaction_id
            if (validateOTP(OTPuser, OTPpin, realm, transaction_id))
            {
                // first true return direct (SMS or Mail token)
                return true;
            } else
            {
                // second request without transaction_id (TOTP)
                return validateOTP(OTPuser, OTPpin, realm, null);
            }
        }

        /// <summary>
        /// Validates a otp pin to the PID3
        /// </summary>
        /// <param name="OTPuser">User name for the token</param>
        /// <param name="OTPpin">PIN for validation</param>
        /// <param name="realm">Domain/realm name</param>
        /// <param name="transaction_id">ID for the coresponding challenge</param>
        /// <returns>true if the pin is correct</returns>
        private bool validateOTP(string OTPuser, string OTPpin, string realm, string transaction_id)
        {
#if DEBUG
            Debug.WriteLine(String.Format("{0} validateOTP({1}, {2}, {3}, {4})", Adapter.debugPrefix, OTPuser, OTPpin, realm, transaction_id));
#endif
            string responseString = "";
            try
            {
                // check if otp contains only numbers
                // Bug #10 - beaks the OTP+PIN combination - removed
                //if (!IsDigitsOnly(OTPpin)) return false;

                NameValueCollection request_header = new NameValueCollection(){
                        {"pass", OTPpin},
                        {"user", OTPuser},
                        {"realm", realm}
                    };
                // add transaction id if challenge request
                if (!string.IsNullOrEmpty(transaction_id)) request_header.Add("transaction_id", transaction_id);
                // send reqeust
                using (WebClient client = new WebClient())
                {
                    byte[] response =
                    client.UploadValues(URL + "/validate/check", request_header);
                    responseString = Encoding.UTF8.GetString(response);
                }
                return (getJsonNode(responseString, "status") == "true" && getJsonNode(responseString, "value") == "true");
            }
            catch (WebException wex)
            {
#if DEBUG
                Debug.WriteLine(System.String.Format("{0} validateOTP() exception: {1})", Adapter.debugPrefix, wex.Message));
#endif
                LogEvent(EventContext.ID3Aprovider, "validateOTP: " + wex.Message + "\n\n" + wex, EventLogEntryType.Error);
                return false;
            }
        }
        /// <summary>
        /// Check whether user has an enrolled token in PID3
        /// </summary>
        /// <param name="OTPuser">User name for the token</param>
        /// <param name="realm">Domain/realm name</param>
        /// <param name="token">Admin token</param>
        /// <returns>true or false</returns>
        public bool hasToken(string OTPuser, string realm, string token)
        {
#if DEBUG
            Debug.WriteLine(String.Format("{0} hasToken({1}, {2}, {3})", Adapter.debugPrefix, OTPuser, realm, token));
#endif
            string responseString = "";
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Headers.Set("Authorization", token);
                    string request = String.Format(URL + "/token/?user={0}&realm={1}", Uri.EscapeDataString(OTPuser), Uri.EscapeDataString(realm));
#if DEBUG
                    Debug.WriteLine(String.Format("{0} hasToken() request: {1})", Adapter.debugPrefix, request));
#endif
                    byte[] response = client.DownloadData(request);
                    responseString = Encoding.UTF8.GetString(response);
#if DEBUG
                    Debug.WriteLine(String.Format("{0} hasToken() responseString: {1})", Adapter.debugPrefix, responseString));
#endif
                    // get list from response
                    string data = getJsonNode(responseString, "tokens");
#if DEBUG
                    Debug.WriteLine(String.Format("{0} hasToken() tokens: {1})", Adapter.debugPrefix, data));
#endif
                    return (data.Length > 0);
                }
            }
            catch (WebException wex)
            {
#if DEBUG
                Debug.WriteLine(System.String.Format("{0} hasToken() exception: {1})", Adapter.debugPrefix, wex.Message));
#endif
                LogEvent(EventContext.ID3Aprovider, "hasToken: " + wex.Message + "\n\n" + wex, EventLogEntryType.Error);
                return false;
            }

        }
        /// <summary>
        /// Trigger for a otp challenge to the PID3
        /// </summary>
        /// <param name="OTPuser">User name for the token</param>
        /// <param name="realm">Domain/realm name</param>
        /// <param name="token">Admin token</param>
        /// <returns>string transaction_id for the challenge</returns>
        public string triggerChallenge(string OTPuser, string realm, string token)
        {
            string responseString = "";
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Headers.Set("PI-Authorization", token);
                    byte[] response =
                    client.UploadValues(URL + "/validate/triggerchallenge", new NameValueCollection()
                    {
                           { "user", OTPuser},
                           { "realm ", realm},
                    });
                    responseString = Encoding.UTF8.GetString(response);
                    // get transaction id from response
                    string transaction_id = getJsonNode(responseString, "transaction_ids");
                    if (transaction_id.Length > 20) transaction_id = transaction_id.Remove(20);
                    // check if use has challenge token
                    return transaction_id;
                }
            }
            catch (WebException wex)
            {
#if DEBUG
                Debug.WriteLine(System.String.Format("{0} triggerChallenge() exception: {1})", Adapter.debugPrefix, wex.Message));
#endif
                LogEvent(EventContext.ID3Aprovider, "triggerChallenge: " + wex.Message + "\n\n" + wex, EventLogEntryType.Error);
                return "";
            }

        }
        /// <summary>
        /// Requests a admin token for administrative tasks
        /// </summary>
        /// <param name="admin_user">Admin user name</param>
        /// <param name="admin_pw">Admin password</param>
        /// <returns>The admin token</returns>
        public string getAuthToken(string admin_user, string admin_pw)
        {
            string responseString = "";
            try
            {
                using (WebClient client = new WebClient())
                {
                    byte[] response =
                    client.UploadValues(URL + "/auth", new NameValueCollection()
                    {
                           { "username", admin_user },
                           { "password", admin_pw }
                    });
                    responseString = Encoding.UTF8.GetString(response);
                }
                return getJsonNode(responseString, "token");
            }
            catch (WebException wex)
            {
                LogEvent(EventContext.ID3Aprovider, "getAuthToken: " + wex.Message + "\n\n" + wex, EventLogEntryType.Error);
                return "";
            }

        }
        /// <summary>
        /// Enrolls a new token to the specified user
        /// </summary>
        /// <param name="OTPuser">User name to enroll the token</param>
        /// <param name="token">Admin token</param>
        /// <returns>Base64 coded token QR image</returns>
        public Dictionary<string, string> enrollHOTPToken(string OTPuser, string realm, string token)
        {
#if DEBUG
            Debug.WriteLine(String.Format("{0} enrollHOTPToken({1}, {2}, {3})", Adapter.debugPrefix, OTPuser, realm, token));
#endif
            string responseString = "";
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Headers.Set("PI-Authorization", token);
                    byte[] response =
                    client.UploadValues(URL + "/token/init", new NameValueCollection()
                    {
                        { "genkey", "1" },
                        { "type ", "hotp" },
                        { "user", OTPuser},
                        { "realm", realm }
                    });
                    responseString = Encoding.UTF8.GetString(response);
                }
                return getQRimage(responseString);
            }
            catch (WebException wex)
            {
#if DEBUG
                Debug.WriteLine(System.String.Format("{0} enrollHOTPToken() exception: {1})", Adapter.debugPrefix, wex.Message));
#endif
                LogEvent(EventContext.ID3Aprovider, "enrollHOTPToken: " + wex.Message + "\n\n" + wex, EventLogEntryType.Error);
                //return getQRimage(responseString);
                return new Dictionary<string, string>();
            }
        }
        /// <summary>
        /// Enrolls a new SMS token to the specified user
        /// </summary>
        /// <param name="OTPuser">User name to enroll the token</param>
        /// <param name="token">Admin token</param>
        /// <returns>Base64 coded token QR image</returns>
        public bool enrollSMSToken(string OTPuser, string realm, string phonenumber, string token)
        {
            string responseString = "";
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Headers.Set("PI-Authorization", token);
                    byte[] response =
                    client.UploadValues(URL + "/token/init?genkey=1", new NameValueCollection()
                    {
                        {"type ", "sms"},
                        {"user", OTPuser},
                        {"realm", realm},
                        {"phone", phonenumber}
                    });
                    responseString = Encoding.UTF8.GetString(response);
                }
                return (getJsonNode(responseString, "status") == "true" && getJsonNode(responseString, "value") == "true");
            }
            catch (WebException wex)
            {
#if DEBUG
                Debug.WriteLine(System.String.Format("{0} enrollSMSToken() exception: {1})", Adapter.debugPrefix, wex.Message));
#endif
                LogEvent(EventContext.ID3Aprovider, "enrollSMSToken: " + wex.Message + "\n\n"+ wex, EventLogEntryType.Error);
                return false;
            }
        }
        /// <summary>
        /// Extracts the img values from the json string
        /// </summary>
        /// <param name="jsonResponse">json string</param>
        /// <returns></returns>
        private Dictionary<string, string> getQRimage(string jsonResponse)
        {
            Dictionary<string, string> imgs = new Dictionary<string, string>();
            var xml = XDocument.Load(JsonReaderWriterFactory.CreateJsonReader(Encoding.ASCII.GetBytes(jsonResponse), new XmlDictionaryReaderQuotas()));
            foreach (XElement element in xml.Descendants("img"))
            {
                imgs.Add(element.Parent.Name.ToString(), element.Value);
            }
            return imgs;
        }

    }
    public class WrongOTPExeption : Exception
    {
        public WrongOTPExeption()
        {

        }

        public WrongOTPExeption(string message) : base(message)
        {
        }

        public WrongOTPExeption(string message, Exception inner) : base(message, inner)
        {

        }
    }
}
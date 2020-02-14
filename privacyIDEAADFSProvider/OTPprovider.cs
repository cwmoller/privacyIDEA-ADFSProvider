using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;
using static privacyIDEAADFSProvider.Helper;

namespace privacyIDEAADFSProvider
{
    public class OTPprovider
    {
        private string URL { get; set; }

        /// <summary>
        /// Class creates a OTPprovider for the privacyIDEA system
        /// </summary>
        /// <param name="privacyIDEAurl">Provide the URL (HTTPS) to the privacyIDEA system</param>
        public OTPprovider(string privacyIDEAurl)
        {
            URL = privacyIDEAurl;
        }

        /// <summary>
        /// Validates a OTP
        /// </summary>
        /// <param name="OTPuser">User name for the token</param>
        /// <param name="OTPpin">PIN for validation</param>
        /// <param name="realm">Domain/realm name</param>
        /// <param name="transactionID">ID for the corresponding challenge</param>
        /// <returns>true if the pin is correct</returns>
        public bool ValidateOTP(string OTPuser, string OTPpin, string realm, string transactionID)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} ValidateOTP({OTPuser}, {OTPpin}, {realm}, {transactionID})");
#endif
            string responseString = "";
            byte[] response;
            int retries = 3;

            NameValueCollection request_header = new NameValueCollection() {
                {"pass", OTPpin},
                {"user", OTPuser},
                {"realm", realm}
            };
            // add transaction_id if challenge request
            if (!string.IsNullOrEmpty(transactionID)) request_header.Add("transaction_id", transactionID);

            do {
                try
                {
                    // send request
                    using (WebClient client = new WebClient())
                    {
                        response = client.UploadValues($"{URL}/validate/check", request_header);
                        responseString = Encoding.UTF8.GetString(response);
                    }
                    return (GetJsonNode(responseString, "status") == "true" && GetJsonNode(responseString, "value") == "true");
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} ValidateOTP() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"ValidateOTP() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return false;
        }

        /// <summary>
        /// Check whether user has an enrolled token in PID3
        /// </summary>
        /// <param name="OTPuser">User name for the token</param>
        /// <param name="realm">Domain/realm name</param>
        /// <param name="token">Admin token</param>
        /// <returns>true or false</returns>
        public bool HasToken(string OTPuser, string realm, string token)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} HasToken({OTPuser}, {realm}, {token})");
#endif
            string request;
            string responseString = "";
            byte[] response;
            string data;
            int retries = 3;

            do {
                try
                {
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Set("Authorization", token);
                        request = $"{URL}/token/?user={Uri.EscapeDataString(OTPuser)}&realm={Uri.EscapeDataString(realm)}";
#if DEBUG
                        Debug.WriteLine($"{debugPrefix} HasToken() request: {request}");
#endif
                        response = client.DownloadData(request);
                        responseString = Encoding.UTF8.GetString(response);
#if DEBUG
                        Debug.WriteLine($"{debugPrefix} HasToken() responseString: {responseString}");
#endif
                        // get list from response
                        data = GetJsonNode(responseString, "tokens");
#if DEBUG
                        Debug.WriteLine($"{debugPrefix} HasToken() tokens: {data}");
#endif
                        return (data.Length > 0);
                    }
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} HasToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"HasToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return false;
        }

        /// <summary>
        /// Trigger for a otp challenge to the PID3
        /// </summary>
        /// <param name="OTPuser">User name for the token</param>
        /// <param name="realm">Domain/realm name</param>
        /// <param name="token">Admin token</param>
        /// <returns>string transaction_id for the challenge</returns>
        public string TriggerChallenge(string OTPuser, string realm, string token)
        {
            string responseString = "";
            byte[] response;
            string transaction_id;
            int retries = 3;

            NameValueCollection request_header = new NameValueCollection() {
                { "user", OTPuser },
                { "realm", realm },
            };

            do {
                try
                {
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Set("PI-Authorization", token);
                        response = client.UploadValues($"{URL}/validate/triggerchallenge", request_header);
                        responseString = Encoding.UTF8.GetString(response);
                        // get transaction id from response
                        transaction_id = GetJsonNode(responseString, "transaction_ids");
                        if (transaction_id.Length > 20) transaction_id = transaction_id.Remove(20);
                        // check if use has challenge token
                        return transaction_id;
                    }
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} TriggerChallenge() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"TriggerChallenge() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return "";
        }

        /// <summary>
        /// Requests a admin token for administrative tasks
        /// </summary>
        /// <param name="adminUser">Admin user name</param>
        /// <param name="adminPass">Admin password</param>
        /// <returns>The admin token</returns>
        public string GetAuthToken(string adminUser = "", string adminPass = "")
        {
            string responseString = "";
            byte[] response;
            int retries = 3;

            NameValueCollection request_header = new NameValueCollection() {
                { "username", adminUser },
                { "password", adminPass }
            };

            do {
                try
                {
                    using (WebClient client = new WebClient())
                    {
                        response = client.UploadValues($"{URL}/auth", request_header);
                        responseString = Encoding.UTF8.GetString(response);
                    }
                    return GetJsonNode(responseString, "token");
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} GetAuthToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"GetAuthToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return "";
        }

        /// <summary>
        /// Enrolls a new token to the specified user
        /// </summary>
        /// <param name="OTPuser">User name to enroll the token</param>
        /// <param name="token">Admin token</param>
        /// <returns>Base64 coded token QR image</returns>
        public Dictionary<string, string> EnrollTOTPToken(string OTPuser, string realm, string token)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} EnrollTOTPToken({OTPuser}, {realm}, {token})");
#endif
            string responseString = "";
            byte[] response;
            int retries = 3;

            NameValueCollection request_header = new NameValueCollection() {
                { "genkey", "1" },
                { "type", "totp" },
                { "user", OTPuser },
                { "realm", realm }
            };

            do {
                try
                {
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Set("PI-Authorization", token);
                        response = client.UploadValues(URL + "/token/init", request_header);
                        responseString = Encoding.UTF8.GetString(response);
#if DEBUG
                        Debug.WriteLine($"{debugPrefix} EnrollTOTPToken() {responseString}");
#endif
                    }
                    return GetQRimage(responseString);
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} EnrollTOTPToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"EnrollTOTPToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return new Dictionary<string, string>();
        }

        /// <summary>
        /// Enrolls a new SMS token to the specified user
        /// </summary>
        /// <param name="OTPuser">User name to enroll the token</param>
        /// <param name="token">Admin token</param>
        /// <returns>Base64 coded token QR image</returns>
        public bool EnrollSMSToken(string OTPuser, string realm, string phonenumber, string token)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} EnrollSMSToken({OTPuser}, {realm}, {phonenumber}, {token})");
#endif

            string responseString = "";
            byte[] response;
            int retries = 3;

            NameValueCollection request_header = new NameValueCollection() {
                { "genkey", "1" },
                { "type", "sms"},
                { "user", OTPuser},
                { "realm", realm},
                { "phone", phonenumber}
            };

            do {
                try
                {
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Set("PI-Authorization", token);
                        response = client.UploadValues($"{URL}/token/init", request_header);
                        responseString = Encoding.UTF8.GetString(response);
#if DEBUG
                        Debug.WriteLine($"{debugPrefix} EnrollSMSToken() {responseString}");
#endif
                    }
                    return (GetJsonNode(responseString, "status") == "true" && GetJsonNode(responseString, "value") == "true");
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} EnrollSMSToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"EnrollSMSToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return false;
        }

    }

}

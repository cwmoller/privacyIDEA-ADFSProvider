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
        private string URL;
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
        /// <param name="transaction_id">ID for the coresponding challenge</param>
        /// <returns>true if the pin is correct</returns>
        public bool validateOTP(string OTPuser, string OTPpin, string realm, string transaction_id)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} validateOTP({OTPuser}, {OTPpin}, {realm}, {transaction_id})");
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
            if (!string.IsNullOrEmpty(transaction_id)) request_header.Add("transaction_id", transaction_id);

            do {
                try
                {
                    // send request
                    using (WebClient client = new WebClient())
                    {
                        response = client.UploadValues($"{URL}/validate/check", request_header);
                        responseString = Encoding.UTF8.GetString(response);
                    }
                    return (getJsonNode(responseString, "status") == "true" && getJsonNode(responseString, "value") == "true");
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} validateOTP() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"validateOTP() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
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
        public bool hasToken(string OTPuser, string realm, string token)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} hasToken({OTPuser}, {realm}, {token})");
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
                        Debug.WriteLine($"{debugPrefix} hasToken() request: {request}");
#endif
                        response = client.DownloadData(request);
                        responseString = Encoding.UTF8.GetString(response);
#if DEBUG
                        Debug.WriteLine($"{debugPrefix} hasToken() responseString: {responseString}");
#endif
                        // get list from response
                        data = getJsonNode(responseString, "tokens");
#if DEBUG
                        Debug.WriteLine($"{debugPrefix} hasToken() tokens: {data}");
#endif
                        return (data.Length > 0);
                    }
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} hasToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"hasToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
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
        public string triggerChallenge(string OTPuser, string realm, string token)
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
                        transaction_id = getJsonNode(responseString, "transaction_ids");
                        if (transaction_id.Length > 20) transaction_id = transaction_id.Remove(20);
                        // check if use has challenge token
                        return transaction_id;
                    }
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} triggerChallenge() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"triggerChallenge() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return "";
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
            byte[] response;
            int retries = 3;

            NameValueCollection request_header = new NameValueCollection() {
                { "username", admin_user },
                { "password", admin_pw }
            };

            do {
                try
                {
                    using (WebClient client = new WebClient())
                    {
                        response = client.UploadValues($"{URL}/auth", request_header);
                        responseString = Encoding.UTF8.GetString(response);
                    }
                    return getJsonNode(responseString, "token");
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} getAuthToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"getAuthToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
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
        public Dictionary<string, string> enrollTOTPToken(string OTPuser, string realm, string token)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} enrollTOTPToken({OTPuser}, {realm}, {token})");
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
                        Debug.WriteLine($"{debugPrefix} enrollTOTPToken() {responseString}");
#endif
                    }
                    return getQRimage(responseString);
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} enrollTOTPToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"enrollTOTPToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
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
        public bool enrollSMSToken(string OTPuser, string realm, string phonenumber, string token)
        {
#if DEBUG
            Debug.WriteLine($"{debugPrefix} enrollSMSToken({OTPuser}, {realm}, {phonenumber}, {token})");
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
                        Debug.WriteLine($"{debugPrefix} enrollSMSToken() {responseString}");
#endif
                    }
                    return (getJsonNode(responseString, "status") == "true" && getJsonNode(responseString, "value") == "true");
                }
                catch (WebException wex)
                {
#if DEBUG
                    Debug.WriteLine($"{debugPrefix} enrollSMSToken() exception(try=={4-retries}): {wex.Message}");
#endif
                    LogEvent($"enrollSMSToken() exception(try=={4-retries}): {wex.Message}", EventLogEntryType.Error);
                }
                Thread.Sleep(100);
            } while (retries-- > 0);
            return false;
        }

    }

}

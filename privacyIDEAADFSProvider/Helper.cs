using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace privacyIDEAADFSProvider
{
    internal static class Helper
    {
        public static string ToDebugString<TKey, TValue>(this IDictionary<TKey, TValue> dictionary)
        {
            return "{" + string.Join(",", dictionary.Select(kv => kv.Key + "=" + kv.Value).ToArray()) + "}";
        }

        /// <summary>
        /// Helper: Creates a log entry in the MS EventLog under Applications
        /// </summary>
        /// <param name="context"></param>
        /// <param name="message"></param>
        /// <param name="type"></param>
        public static void LogEvent(EventContext context, string message, EventLogEntryType type)
        {
            using (EventLog eventLog = new EventLog("AD FS/Admin"))
            {
                eventLog.Source = "privacyIDEAProvider";
                eventLog.WriteEntry(message, type, (int)context, 0);
            }
        }
        public enum EventContext
        {
            ID3Aprovider = 9901,
            ID3A_ADFSadapter = 9902
        }

        /////////////////////////////////////////////////////////////////
        // ------- HELPER ------ 
        /////////////////////////////////////////////////////////////////
        /// <summary>
        /// Validates the pin for a numeric only string
        /// </summary>
        /// <param name="str">string to validate</param>
        /// <returns>True if string only contains numbers</returns>
        public static bool IsDigitsOnly(string str)
        {
            foreach (char c in str)
            {
                if (c < '0' || c > '9')
                    return false;
            }
            if (str.Length > 8) return false;

            return true;
        }
        /// <summary>
        /// Get json information form a defined node
        /// </summary>
        /// <param name="jsonResponse">json string</param>
        /// <param name="nodename">node name of the json field</param>
        /// <returns>returns the value (inner text) from the defined node</returns>
        public static string getJsonNode(string jsonResponse, string nodename)
        {
            try
            {
                var xml = XDocument.Load(JsonReaderWriterFactory.CreateJsonReader(Encoding.ASCII.GetBytes(jsonResponse), new XmlDictionaryReaderQuotas()));
                return xml.Descendants(nodename).Single().Value;
            }
            catch (Exception ex)
            {
#if DEBUG
                Debug.WriteLine(System.String.Format("{0} getJsonNode() exception: {1})", Adapter.debugPrefix, ex.Message));
#endif
                LogEvent(EventContext.ID3Aprovider, "getJsonNode: " + ex.Message + "\n\n" + ex, EventLogEntryType.Error);
                return "";
            }
        }
    }
}


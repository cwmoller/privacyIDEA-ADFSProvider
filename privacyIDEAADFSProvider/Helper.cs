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
        public const string debugPrefix = "ID3A: ";
        public const int ID3Aprovider = 9901;
        private static EventLog eventLog = null;

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
        public static void LogEvent(string message, EventLogEntryType type)
        {
            if (eventLog == null)
            {
                eventLog = new EventLog("AD FS/Admin");
            }
            using (eventLog)
            {
                eventLog.Source = "privacyIDEAProvider";
                eventLog.WriteEntry(message, type, ID3Aprovider, 0);
            }
        }

        /// <summary>
        /// Get JSON information from a defined node
        /// </summary>
        /// <param name="jsonResponse">JSON string</param>
        /// <param name="nodename">node name of the JSON field</param>
        /// <returns>returns the value (inner text) from the defined node</returns>
        public static string GetJsonNode(string jsonResponse, string nodename)
        {
            try
            {
                XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(Encoding.ASCII.GetBytes(jsonResponse), new XmlDictionaryReaderQuotas());
                XDocument xml = XDocument.Load(reader);
                reader.Dispose();
                return xml.Descendants(nodename).Single().Value;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
#if DEBUG
                Debug.WriteLine($"{debugPrefix} GetJsonNode() exception: {ex.Message}");
#endif
                LogEvent($"GetJsonNode() exception: {ex.Message}", EventLogEntryType.Error);
                return "";
            }
        }

        /// <summary>
        /// Extracts the img values from the JSON string
        /// </summary>
        /// <param name="jsonResponse">JSON string</param>
        /// <returns></returns>
        public static Dictionary<string, string> GetQRimage(string jsonResponse)
        {
            Dictionary<string, string> imgs = new Dictionary<string, string>();
            XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(Encoding.ASCII.GetBytes(jsonResponse), new XmlDictionaryReaderQuotas());
            XDocument xml = XDocument.Load(reader);
            reader.Dispose();
            foreach (XElement element in xml.Descendants("img"))
            {
                imgs.Add(element.Parent.Name.ToString(), element.Value);
            }
            return imgs;
        }
    }
}


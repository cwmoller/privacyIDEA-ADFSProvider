using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

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
    }
}

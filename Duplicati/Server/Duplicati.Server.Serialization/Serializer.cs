using System.Globalization;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Duplicati.Server.Serialization
{    
    public class Serializer
    {
        protected static readonly JsonSerializer m_jsonSerializer = JsonSerializer.Create(
            new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
                Culture = CultureInfo.InvariantCulture,
                Converters = new JsonConverter[] {
                    new DayOfWeekConcerter(),
                    new StringEnumConverter(),
                    new SerializableStatusCreator(),
                    new SettingsCreator(),
                    new FilterCreator(),
                    new NotificationCreator(),
                }.ToList()
            }
        );

        public static void SerializeJson(TextWriter textWriter, object o)
        {
            var jsonWriter = new JsonTextWriter(textWriter);
            m_jsonSerializer.Serialize(jsonWriter, o);
            jsonWriter.Flush();
        }

        public static T Deserialize<T>(TextReader textReader)
        {
            using var jsonReader = new JsonTextReader(textReader);
            return m_jsonSerializer.Deserialize<T>(jsonReader);
        }

        public static T Deserialize<T>(Stream jsonStream)
        {
            using StreamReader streamReader = new StreamReader(jsonStream);
            return Deserialize<T>(streamReader);
        }
    }
}

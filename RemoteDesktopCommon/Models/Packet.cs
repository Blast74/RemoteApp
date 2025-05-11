using System;
using Newtonsoft.Json;

namespace RemoteDesktopCommon.Models
{
    public enum PacketType
    {
        ScreenData,
        MouseInput,
        KeyboardInput,
        FileTransfer,
        AudioData,
        ChatMessage,
        Authentication,
        Control,
        Heartbeat
    }

    public class Packet
    {
        public PacketType Type { get; set; }
        public int SequenceNumber { get; set; }
        public bool RequiresAck { get; set; }
        public byte[] Payload { get; set; }
        public string SessionId { get; set; }
        public DateTime Timestamp { get; set; }
        public QualityLevel QualityLevel { get; set; }

        public Packet()
        {
            Timestamp = DateTime.UtcNow;
        }

        public static Packet CreateScreenDataPacket(byte[] screenData, int sequenceNumber, QualityLevel quality)
        {
            return new Packet
            {
                Type = PacketType.ScreenData,
                SequenceNumber = sequenceNumber,
                RequiresAck = true,
                Payload = screenData,
                QualityLevel = quality
            };
        }

        public static Packet CreateInputPacket(byte[] inputData, PacketType inputType)
        {
            return new Packet
            {
                Type = inputType,
                RequiresAck = true,
                Payload = inputData
            };
        }

        public static Packet CreateHeartbeat(string sessionId)
        {
            return new Packet
            {
                Type = PacketType.Heartbeat,
                SessionId = sessionId,
                RequiresAck = false
            };
        }
    }

    public enum QualityLevel
    {
        Low = 10,
        Medium = 50,
        High = 75,
        Ultra = 100
    }
}

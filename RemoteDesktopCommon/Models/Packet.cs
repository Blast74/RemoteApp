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
        public byte[]? Payload { get; set; }
        public string? SessionId { get; set; }
        public DateTime Timestamp { get; set; }
        public QualityLevel QualityLevel { get; set; }

        public Packet()
        {
            Timestamp = DateTime.UtcNow;
        }

        public static Packet CreateScreenDataPacket(byte[] screenData, int sequenceNumber, QualityLevel quality)
        {
            ArgumentNullException.ThrowIfNull(screenData);

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
            ArgumentNullException.ThrowIfNull(inputData);

            if (inputType != PacketType.MouseInput && inputType != PacketType.KeyboardInput)
            {
                throw new ArgumentException("Invalid input packet type", nameof(inputType));
            }

            return new Packet
            {
                Type = inputType,
                RequiresAck = true,
                Payload = inputData
            };
        }

        public static Packet CreateHeartbeat(string sessionId)
        {
            ArgumentNullException.ThrowIfNull(sessionId);

            return new Packet
            {
                Type = PacketType.Heartbeat,
                SessionId = sessionId,
                RequiresAck = false
            };
        }

        public static Packet CreateControlPacket(byte[] controlData)
        {
            ArgumentNullException.ThrowIfNull(controlData);

            return new Packet
            {
                Type = PacketType.Control,
                RequiresAck = true,
                Payload = controlData
            };
        }

        public static Packet CreateAuthenticationPacket(byte[] authData, string sessionId)
        {
            ArgumentNullException.ThrowIfNull(authData);
            ArgumentNullException.ThrowIfNull(sessionId);

            return new Packet
            {
                Type = PacketType.Authentication,
                RequiresAck = true,
                Payload = authData,
                SessionId = sessionId
            };
        }

        public static Packet CreateFileTransferPacket(byte[] fileData, string sessionId)
        {
            ArgumentNullException.ThrowIfNull(fileData);
            ArgumentNullException.ThrowIfNull(sessionId);

            return new Packet
            {
                Type = PacketType.FileTransfer,
                RequiresAck = true,
                Payload = fileData,
                SessionId = sessionId
            };
        }

        public static Packet CreateAudioPacket(byte[] audioData)
        {
            ArgumentNullException.ThrowIfNull(audioData);

            return new Packet
            {
                Type = PacketType.AudioData,
                RequiresAck = false,
                Payload = audioData
            };
        }

        public static Packet CreateChatPacket(byte[] chatData, string sessionId)
        {
            ArgumentNullException.ThrowIfNull(chatData);
            ArgumentNullException.ThrowIfNull(sessionId);

            return new Packet
            {
                Type = PacketType.ChatMessage,
                RequiresAck = true,
                Payload = chatData,
                SessionId = sessionId
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

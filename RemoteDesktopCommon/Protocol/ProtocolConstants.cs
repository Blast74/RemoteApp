namespace RemoteDesktopCommon.Protocol
{
    public static class ProtocolConstants
    {
        // Network Settings
        public const int DEFAULT_PORT = 8950;
        public const int HEARTBEAT_INTERVAL_MS = 5000;
        public const int CONNECTION_TIMEOUT_MS = 15000;
        public const int MAX_PACKET_SIZE = 65507; // Maximum UDP packet size
        
        // Quality and Performance
        public const int TARGET_FPS = 30;
        public const int MIN_QUALITY = 10;
        public const int MAX_QUALITY = 100;
        public const double PACKET_LOSS_THRESHOLD = 0.05; // 5% packet loss threshold for TCP fallback
        
        // Reliability Settings
        public const int MAX_RETRIES = 3;
        public const int ACK_TIMEOUT_MS = 100;
        public const int SEQUENCE_NUMBER_MODULO = 65536; // 2^16
        
        // Security
        public const int AES_KEY_SIZE = 256;
        public const int AES_BLOCK_SIZE = 128;
        public const string ENCRYPTION_ALGORITHM = "AES";
        
        // Stream Types
        public const byte STREAM_TYPE_VIDEO = 0x01;
        public const byte STREAM_TYPE_AUDIO = 0x02;
        public const byte STREAM_TYPE_INPUT = 0x03;
        public const byte STREAM_TYPE_FILE = 0x04;
        public const byte STREAM_TYPE_CONTROL = 0x05;
        
        // QoS Priority Levels (0-7, higher is more important)
        public const byte PRIORITY_CONTROL = 7;
        public const byte PRIORITY_INPUT = 6;
        public const byte PRIORITY_AUDIO = 5;
        public const byte PRIORITY_VIDEO = 4;
        public const byte PRIORITY_FILE = 2;
        
        // Buffer Sizes
        public const int VIDEO_BUFFER_SIZE = 1024 * 1024 * 8;  // 8MB
        public const int AUDIO_BUFFER_SIZE = 1024 * 64;        // 64KB
        public const int INPUT_BUFFER_SIZE = 1024;             // 1KB
        
        // Timeouts and Intervals
        public const int QUALITY_ADJUSTMENT_INTERVAL_MS = 1000;
        public const int BANDWIDTH_MEASUREMENT_INTERVAL_MS = 2000;
        public const int CLEANUP_INTERVAL_MS = 30000;
    }
}

using System;
using System.Drawing;

namespace RemoteDesktopCommon.Models
{
    public class ScreenFrame
    {
        public byte[]? EncodedData { get; set; }
        public Rectangle[]? UpdatedRegions { get; set; }
        public DateTime Timestamp { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public string? EncodingFormat { get; set; }
        public int Quality { get; set; }

        public ScreenFrame()
        {
            Timestamp = DateTime.UtcNow;
        }

        public int GetDataSize()
        {
            return EncodedData?.Length ?? 0;
        }

        public bool HasUpdates()
        {
            return UpdatedRegions != null && UpdatedRegions.Length > 0;
        }

        public static ScreenFrame CreateFrame(
            byte[] encodedData, 
            Rectangle[] updatedRegions, 
            int width, 
            int height, 
            string encodingFormat, 
            int quality)
        {
            ArgumentNullException.ThrowIfNull(encodedData);
            ArgumentNullException.ThrowIfNull(updatedRegions);
            ArgumentNullException.ThrowIfNull(encodingFormat);

            return new ScreenFrame
            {
                EncodedData = encodedData,
                UpdatedRegions = updatedRegions,
                Width = width,
                Height = height,
                EncodingFormat = encodingFormat,
                Quality = quality
            };
        }

        public void Dispose()
        {
            EncodedData = null;
            UpdatedRegions = null;
        }
    }
}

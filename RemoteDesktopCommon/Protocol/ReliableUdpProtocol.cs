using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using RemoteDesktopCommon.Models;

namespace RemoteDesktopCommon.Protocol
{
    public class ReliableUdpProtocol : IDisposable
    {
        private readonly ILogger<ReliableUdpProtocol> _logger;
        private UdpClient _udpClient;
        private readonly ConcurrentDictionary<int, PendingPacket> _pendingPackets;
        private readonly ConcurrentDictionary<string, SessionState> _sessions;
        private readonly CancellationTokenSource _cancellationTokenSource;
        
        private bool _useTcpFallback;
        private TcpListener _tcpListener;
        private TcpClient _tcpClient;
        private double _packetLossRate;

        public event EventHandler<Packet> PacketReceived;
        public event EventHandler<string> ConnectionStateChanged;

        public ReliableUdpProtocol(ILogger<ReliableUdpProtocol> logger)
        {
            _logger = logger;
            _pendingPackets = new ConcurrentDictionary<int, PendingPacket>();
            _sessions = new ConcurrentDictionary<string, SessionState>();
            _cancellationTokenSource = new CancellationTokenSource();
            _packetLossRate = 0;
        }

        public async Task StartServer(int port)
        {
            try
            {
                _udpClient = new UdpClient(port);
                _tcpListener = new TcpListener(IPAddress.Any, port);
                _tcpListener.Start();

                _ = StartPacketReceiving();
                _ = StartTcpAcceptLoop();
                _ = StartMaintenanceLoop();

                _logger.LogInformation($"Server started on port {port}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start server");
                throw;
            }
        }

        public async Task Connect(string host, int port)
        {
            try
            {
                _udpClient = new UdpClient();
                await _udpClient.ConnectAsync(host, port);

                _ = StartPacketReceiving();
                _ = StartMaintenanceLoop();

                _logger.LogInformation($"Connected to {host}:{port}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to connect to server");
                throw;
            }
        }

        public async Task SendPacket(Packet packet)
        {
            try
            {
                if (_useTcpFallback)
                {
                    await SendViaTcp(packet);
                    return;
                }

                if (packet.RequiresAck)
                {
                    var pendingPacket = new PendingPacket
                    {
                        Packet = packet,
                        Timestamp = DateTime.UtcNow,
                        RetryCount = 0
                    };
                    _pendingPackets[packet.SequenceNumber] = pendingPacket;
                }

                byte[] data = PacketSerializer.Serialize(packet);
                await _udpClient.SendAsync(data, data.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send packet");
                throw;
            }
        }

        private async Task SendViaTcp(Packet packet)
        {
            try
            {
                if (_tcpClient?.Connected != true)
                {
                    _logger.LogWarning("TCP client not connected. Attempting to establish TCP connection...");
                    return;
                }

                byte[] data = PacketSerializer.Serialize(packet);
                byte[] lengthPrefix = BitConverter.GetBytes(data.Length);

                NetworkStream stream = _tcpClient.GetStream();
                await stream.WriteAsync(lengthPrefix, 0, lengthPrefix.Length);
                await stream.WriteAsync(data, 0, data.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send packet via TCP");
                throw;
            }
        }

        private async Task StartPacketReceiving()
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult result = await _udpClient.ReceiveAsync();
                    var packet = PacketSerializer.Deserialize(result.Buffer);

                    if (packet.RequiresAck)
                    {
                        await SendAcknowledgement(packet.SequenceNumber, result.RemoteEndPoint);
                    }

                    UpdatePacketLossRate();
                    PacketReceived?.Invoke(this, packet);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error receiving packet");
                }
            }
        }

        private async Task StartTcpAcceptLoop()
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await _tcpListener.AcceptTcpClientAsync();
                    _ = HandleTcpClient(client);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error accepting TCP client");
                }
            }
        }

        private async Task HandleTcpClient(TcpClient client)
        {
            try
            {
                NetworkStream stream = client.GetStream();
                byte[] lengthBuffer = new byte[4];

                while (!_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    await stream.ReadAsync(lengthBuffer, 0, 4);
                    int length = BitConverter.ToInt32(lengthBuffer, 0);

                    byte[] packetData = new byte[length];
                    await stream.ReadAsync(packetData, 0, length);

                    var packet = PacketSerializer.Deserialize(packetData);
                    PacketReceived?.Invoke(this, packet);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling TCP client");
            }
            finally
            {
                client.Close();
            }
        }

        private async Task StartMaintenanceLoop()
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    CheckForTimeouts();
                    CheckPacketLossRate();
                    CleanupSessions();
                    await Task.Delay(1000);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in maintenance loop");
                }
            }
        }

        private void CheckPacketLossRate()
        {
            if (_packetLossRate > ProtocolConstants.PACKET_LOSS_THRESHOLD && !_useTcpFallback)
            {
                _useTcpFallback = true;
                _logger.LogWarning($"Packet loss rate ({_packetLossRate:P}) exceeded threshold. Switching to TCP.");
                ConnectionStateChanged?.Invoke(this, "Switched to TCP mode due to high packet loss");
            }
            else if (_packetLossRate < ProtocolConstants.PACKET_LOSS_THRESHOLD && _useTcpFallback)
            {
                _useTcpFallback = false;
                _logger.LogInformation("Packet loss rate normalized. Switching back to UDP.");
                ConnectionStateChanged?.Invoke(this, "Switched to UDP mode");
            }
        }

        private void UpdatePacketLossRate()
        {
            // Simple exponential moving average
            const double alpha = 0.1;
            int lostPackets = _pendingPackets.Count(p => p.Value.RetryCount > 0);
            int totalPackets = Math.Max(1, _pendingPackets.Count);
            double currentLossRate = (double)lostPackets / totalPackets;
            _packetLossRate = (alpha * currentLossRate) + ((1 - alpha) * _packetLossRate);
        }

        private async Task SendAcknowledgement(int sequenceNumber, IPEndPoint endpoint)
        {
            var ackPacket = new Packet
            {
                Type = PacketType.Control,
                SequenceNumber = sequenceNumber,
                RequiresAck = false
            };

            byte[] data = PacketSerializer.Serialize(ackPacket);
            await _udpClient.SendAsync(data, data.Length, endpoint);
        }

        private void CheckForTimeouts()
        {
            var now = DateTime.UtcNow;
            foreach (var kvp in _pendingPackets)
            {
                var pending = kvp.Value;
                if ((now - pending.Timestamp).TotalMilliseconds > ProtocolConstants.ACK_TIMEOUT_MS)
                {
                    if (pending.RetryCount >= ProtocolConstants.MAX_RETRIES)
                    {
                        _pendingPackets.TryRemove(kvp.Key, out _);
                        _logger.LogWarning($"Packet {kvp.Key} exceeded max retries");
                    }
                    else
                    {
                        pending.RetryCount++;
                        pending.Timestamp = now;
                        _ = SendPacket(pending.Packet);
                    }
                }
            }
        }

        private void CleanupSessions()
        {
            var now = DateTime.UtcNow;
            foreach (var kvp in _sessions)
            {
                if ((now - kvp.Value.LastActivity).TotalMilliseconds > ProtocolConstants.CONNECTION_TIMEOUT_MS)
                {
                    _sessions.TryRemove(kvp.Key, out _);
                    _logger.LogInformation($"Session {kvp.Key} timed out");
                }
            }
        }

        public void Dispose()
        {
            _cancellationTokenSource.Cancel();
            _udpClient?.Close();
            _tcpListener?.Stop();
            _tcpClient?.Close();
        }

        private class PendingPacket
        {
            public Packet Packet { get; set; }
            public DateTime Timestamp { get; set; }
            public int RetryCount { get; set; }
        }

        private class SessionState
        {
            public string SessionId { get; set; }
            public DateTime LastActivity { get; set; }
            public IPEndPoint EndPoint { get; set; }
        }
    }

    internal static class PacketSerializer
    {
        public static byte[] Serialize(Packet packet)
        {
            // Implementation would use a binary serialization format
            // This is a placeholder - actual implementation would need proper serialization
            return null;
        }

        public static Packet Deserialize(byte[] data)
        {
            // Implementation would use a binary deserialization format
            // This is a placeholder - actual implementation would need proper deserialization
            return null;
        }
    }
}

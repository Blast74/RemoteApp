using System;
using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace RemoteDesktopCommon.Security
{
    public class AuthenticationManager
    {
        private readonly ILogger<AuthenticationManager> _logger;
        private readonly string _jwtSecret;
        private readonly ConcurrentDictionary<string, UserSession> _activeSessions;
        private readonly ConcurrentDictionary<string, DateTime> _revokedTokens;
        private readonly TimeSpan _tokenLifetime = TimeSpan.FromHours(12);
        private readonly TimeSpan _totpTimeStep = TimeSpan.FromSeconds(30);

        public AuthenticationManager(ILogger<AuthenticationManager> logger, string jwtSecret)
        {
            _logger = logger;
            _jwtSecret = jwtSecret;
            _activeSessions = new ConcurrentDictionary<string, UserSession>();
            _revokedTokens = new ConcurrentDictionary<string, DateTime>();
        }

        public async Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request)
        {
            try
            {
                switch (request.Method)
                {
                    case AuthenticationMethod.Password:
                        return await ValidatePasswordAsync(request);
                    case AuthenticationMethod.Certificate:
                        return await ValidateCertificateAsync(request);
                    case AuthenticationMethod.OAuth:
                        return await ValidateOAuthTokenAsync(request);
                    case AuthenticationMethod.TOTP:
                        return await ValidateTOTPAsync(request);
                    default:
                        throw new NotSupportedException($"Authentication method {request.Method} not supported");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed");
                return new AuthenticationResult { Success = false, ErrorMessage = "Authentication failed" };
            }
        }

        private async Task<AuthenticationResult> ValidatePasswordAsync(AuthenticationRequest request)
        {
            // In a real implementation, this would validate against a secure database
            // For demo purposes, we're using a simple hash comparison
            var hashedPassword = HashPassword(request.Password, request.Username);
            
            // TODO: Compare with stored hash from database
            var isValid = true; // Placeholder

            if (isValid)
            {
                var token = GenerateJwtToken(request.Username);
                var session = CreateSession(request.Username, token);
                return new AuthenticationResult
                {
                    Success = true,
                    Token = token,
                    SessionId = session.SessionId
                };
            }

            return new AuthenticationResult { Success = false, ErrorMessage = "Invalid credentials" };
        }

        private async Task<AuthenticationResult> ValidateCertificateAsync(AuthenticationRequest request)
        {
            try
            {
                var cert = new X509Certificate2(request.CertificateData);
                
                // Verify certificate is valid and trusted
                if (cert.Verify())
                {
                    var token = GenerateJwtToken(cert.Subject);
                    var session = CreateSession(cert.Subject, token);
                    return new AuthenticationResult
                    {
                        Success = true,
                        Token = token,
                        SessionId = session.SessionId
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate validation failed");
            }

            return new AuthenticationResult { Success = false, ErrorMessage = "Invalid certificate" };
        }

        private async Task<AuthenticationResult> ValidateOAuthTokenAsync(AuthenticationRequest request)
        {
            // In a real implementation, this would validate with the OAuth provider
            // For demo purposes, we're assuming the token is valid
            var isValid = true; // Placeholder
            
            if (isValid)
            {
                var token = GenerateJwtToken(request.Username);
                var session = CreateSession(request.Username, token);
                return new AuthenticationResult
                {
                    Success = true,
                    Token = token,
                    SessionId = session.SessionId
                };
            }

            return new AuthenticationResult { Success = false, ErrorMessage = "Invalid OAuth token" };
        }

        private async Task<AuthenticationResult> ValidateTOTPAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.TOTPCode))
            {
                return new AuthenticationResult { Success = false, ErrorMessage = "TOTP code required" };
            }

            // In a real implementation, this would validate against stored TOTP secret
            var isValid = ValidateTOTPCode(request.TOTPCode, "user_secret_key"); // Placeholder

            if (isValid)
            {
                var token = GenerateJwtToken(request.Username);
                var session = CreateSession(request.Username, token);
                return new AuthenticationResult
                {
                    Success = true,
                    Token = token,
                    SessionId = session.SessionId
                };
            }

            return new AuthenticationResult { Success = false, ErrorMessage = "Invalid TOTP code" };
        }

        private string GenerateJwtToken(string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.Add(_tokenLifetime),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private UserSession CreateSession(string username, string token)
        {
            var session = new UserSession
            {
                SessionId = Guid.NewGuid().ToString(),
                Username = username,
                Token = token,
                Created = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow
            };

            _activeSessions.TryAdd(session.SessionId, session);
            return session;
        }

        private string HashPassword(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var saltedPassword = $"{password}{salt}";
                var bytes = Encoding.UTF8.GetBytes(saltedPassword);
                var hash = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }

        private bool ValidateTOTPCode(string code, string secretKey)
        {
            // In a real implementation, this would use a proper TOTP algorithm
            // For demo purposes, we're using a simple time-based comparison
            var currentInterval = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / (long)_totpTimeStep.TotalSeconds;
            var expectedCode = GenerateTOTPCode(secretKey, currentInterval);
            return code == expectedCode;
        }

        private string GenerateTOTPCode(string secretKey, long interval)
        {
            // This is a simplified TOTP implementation
            // In production, use a proper TOTP library
            using (var hmac = new HMACSHA1(Encoding.ASCII.GetBytes(secretKey)))
            {
                var intervalBytes = BitConverter.GetBytes(interval);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(intervalBytes);
                }
                var hash = hmac.ComputeHash(intervalBytes);
                var offset = hash[hash.Length - 1] & 0xf;
                var binary =
                    ((hash[offset] & 0x7f) << 24) |
                    ((hash[offset + 1] & 0xff) << 16) |
                    ((hash[offset + 2] & 0xff) << 8) |
                    (hash[offset + 3] & 0xff);
                var otp = binary % 1000000;
                return otp.ToString("D6");
            }
        }

        public bool ValidateToken(string token)
        {
            if (_revokedTokens.ContainsKey(token))
            {
                return false;
            }

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtSecret);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void RevokeToken(string token)
        {
            _revokedTokens.TryAdd(token, DateTime.UtcNow);
        }

        private class UserSession
        {
            public string SessionId { get; set; }
            public string Username { get; set; }
            public string Token { get; set; }
            public DateTime Created { get; set; }
            public DateTime LastActivity { get; set; }
        }
    }

    public class AuthenticationRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public AuthenticationMethod Method { get; set; }
        public byte[] CertificateData { get; set; }
        public string OAuthToken { get; set; }
        public string TOTPCode { get; set; }
    }

    public class AuthenticationResult
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public string SessionId { get; set; }
        public string ErrorMessage { get; set; }
    }

    public enum AuthenticationMethod
    {
        Password,
        Certificate,
        OAuth,
        TOTP
    }
}

using System;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace RemoteDesktopCommon.Config
{
    public class AppSettings
    {
        public NetworkSettings Network { get; set; } = new NetworkSettings();
        public SecuritySettings Security { get; set; } = new SecuritySettings();
        public StreamSettings Stream { get; set; } = new StreamSettings();
        public LoggingSettings Logging { get; set; } = new LoggingSettings();
        public AuthenticationSettings Authentication { get; set; } = new AuthenticationSettings();

        public class NetworkSettings
        {
            [Range(1024, 65535)]
            public int Port { get; set; } = 8950;

            [Range(1, 60000)]
            public int HeartbeatInterval { get; set; } = 5000;

            [Range(1000, 300000)]
            public int ConnectionTimeout { get; set; } = 15000;

            [Range(1, 100)]
            public int MaxRetries { get; set; } = 3;

            [Range(10, 1000)]
            public int AckTimeout { get; set; } = 100;

            public bool EnableTcpFallback { get; set; } = true;

            [Range(0.01, 1.0)]
            public double PacketLossThreshold { get; set; } = 0.05;
        }

        public class SecuritySettings
        {
            [Required]
            public string EncryptionKey { get; set; }

            public bool RequireEncryption { get; set; } = true;

            [Range(128, 256)]
            public int KeySize { get; set; } = 256;

            public string CertificatePath { get; set; }

            public string CertificatePassword { get; set; }

            public bool ValidateCertificates { get; set; } = true;
        }

        public class StreamSettings
        {
            [Range(1, 60)]
            public int TargetFps { get; set; } = 30;

            [Range(10, 100)]
            public int InitialQuality { get; set; } = 75;

            [Range(1, 100)]
            public int MinQuality { get; set; } = 10;

            [Range(1, 100)]
            public int MaxQuality { get; set; } = 100;

            public bool EnableHardwareEncoding { get; set; } = true;

            public string PreferredEncoder { get; set; } = "H264";

            [Range(128, 10240)]
            public int VideoBufferSize { get; set; } = 8192;

            [Range(16, 1024)]
            public int AudioBufferSize { get; set; } = 64;

            public bool EnableDeltaEncoding { get; set; } = true;
        }

        public class LoggingSettings
        {
            public string LogLevel { get; set; } = "Information";

            public bool EnableFileLogging { get; set; } = true;

            public string LogFilePath { get; set; } = "logs/remote_desktop.log";

            public bool EnableConsoleLogging { get; set; } = true;

            [Range(1, 100)]
            public int MaxLogFiles { get; set; } = 10;

            [Range(1, 1000)]
            public int MaxFileSizeMB { get; set; } = 100;
        }

        public class AuthenticationSettings
        {
            [Required]
            public string JwtSecret { get; set; }

            [Range(1, 24)]
            public int TokenExpirationHours { get; set; } = 12;

            public bool RequireTwoFactor { get; set; } = false;

            public bool AllowPasswordAuth { get; set; } = true;

            public bool AllowCertificateAuth { get; set; } = true;

            public OAuthSettings OAuth { get; set; } = new OAuthSettings();

            public LdapSettings Ldap { get; set; } = new LdapSettings();
        }

        public class OAuthSettings
        {
            public bool Enabled { get; set; } = false;

            public GoogleOAuthSettings Google { get; set; } = new GoogleOAuthSettings();
            public MicrosoftOAuthSettings Microsoft { get; set; } = new MicrosoftOAuthSettings();
            public GitHubOAuthSettings GitHub { get; set; } = new GitHubOAuthSettings();
        }

        public class GoogleOAuthSettings
        {
            public bool Enabled { get; set; } = false;
            public string ClientId { get; set; }
            public string ClientSecret { get; set; }
        }

        public class MicrosoftOAuthSettings
        {
            public bool Enabled { get; set; } = false;
            public string ClientId { get; set; }
            public string ClientSecret { get; set; }
            public string TenantId { get; set; }
        }

        public class GitHubOAuthSettings
        {
            public bool Enabled { get; set; } = false;
            public string ClientId { get; set; }
            public string ClientSecret { get; set; }
        }

        public class LdapSettings
        {
            public bool Enabled { get; set; } = false;
            public string Server { get; set; }
            public int Port { get; set; } = 389;
            public bool UseSsl { get; set; } = true;
            public string BaseDn { get; set; }
            public string BindDn { get; set; }
            public string BindPassword { get; set; }
            public string UserFilter { get; set; } = "(objectClass=person)";
            public bool EnableCache { get; set; } = true;
            public int CacheExpirationMinutes { get; set; } = 30;
        }

        public void Validate()
        {
            var context = new ValidationContext(this, serviceProvider: null, items: null);
            Validator.ValidateObject(this, context, validateAllProperties: true);
        }

        public static AppSettings LoadFromJson(string json)
        {
            var settings = JsonConvert.DeserializeObject<AppSettings>(json);
            settings.Validate();
            return settings;
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }
}

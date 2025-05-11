using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace RemoteDesktopCommon.Config
{
    public class ConfigWatcher : IDisposable
    {
        private readonly ILogger<ConfigWatcher> _logger;
        private readonly string _configPath;
        private readonly FileSystemWatcher _watcher;
        private readonly SemaphoreSlim _reloadLock;
        private AppSettings? _currentSettings;
        private readonly Timer _validationTimer;
        private bool _isReloading;

        public event EventHandler<AppSettings>? ConfigurationChanged;
        public event EventHandler<Exception>? ConfigurationError;

        public AppSettings CurrentSettings => _currentSettings ?? throw new InvalidOperationException("Settings not initialized");

        public ConfigWatcher(ILogger<ConfigWatcher> logger, string configPath)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _configPath = configPath ?? throw new ArgumentNullException(nameof(configPath));
            _reloadLock = new SemaphoreSlim(1, 1);
            
            var directory = Path.GetDirectoryName(_configPath) ?? throw new ArgumentException("Invalid config path", nameof(configPath));
            
            // Initialize file system watcher
            _watcher = new FileSystemWatcher
            {
                Path = directory,
                Filter = Path.GetFileName(_configPath),
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };

            // Set up periodic validation timer
            _validationTimer = new Timer(ValidateConfiguration, null, 
                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

            InitializeWatcher();
            LoadConfiguration();
        }

        private void InitializeWatcher()
        {
            _watcher.Changed += async (s, e) => await OnConfigFileChanged(e);
            _watcher.Created += async (s, e) => await OnConfigFileChanged(e);
            _watcher.Error += OnWatcherError;

            try
            {
                _watcher.EnableRaisingEvents = true;
                _logger.LogInformation($"Started watching configuration file: {_configPath}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize configuration watcher");
                throw;
            }
        }

        private async Task OnConfigFileChanged(FileSystemEventArgs e)
        {
            if (_isReloading)
                return;

            try
            {
                _isReloading = true;
                await Task.Delay(100); // Brief delay to ensure file is completely written

                await _reloadLock.WaitAsync();
                try
                {
                    await ReloadConfiguration();
                }
                finally
                {
                    _reloadLock.Release();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling configuration file change");
                ConfigurationError?.Invoke(this, ex);
            }
            finally
            {
                _isReloading = false;
            }
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            var exception = e.GetException();
            _logger.LogError(exception, "File system watcher error");
            ConfigurationError?.Invoke(this, exception);
        }

        private async Task ReloadConfiguration()
        {
            try
            {
                // Implement retry logic for file access
                const int maxRetries = 3;
                const int retryDelayMs = 100;

                for (int i = 0; i < maxRetries; i++)
                {
                    try
                    {
                        LoadConfiguration();
                        break;
                    }
                    catch (IOException) when (i < maxRetries - 1)
                    {
                        await Task.Delay(retryDelayMs * (i + 1));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reload configuration");
                ConfigurationError?.Invoke(this, ex);
            }
        }

        private void LoadConfiguration()
        {
            try
            {
                string jsonContent = File.ReadAllText(_configPath);
                var newSettings = AppSettings.LoadFromJson(jsonContent);
                
                // Validate new settings before applying
                newSettings.Validate();

                var oldSettings = _currentSettings;
                _currentSettings = newSettings;

                _logger.LogInformation("Configuration reloaded successfully");
                ConfigurationChanged?.Invoke(this, newSettings);

                // Log significant changes
                if (oldSettings != null)
                {
                    LogConfigurationChanges(oldSettings, newSettings);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load configuration");
                throw;
            }
        }

        private void LogConfigurationChanges(AppSettings oldSettings, AppSettings newSettings)
        {
            if (oldSettings.Network.Port != newSettings.Network.Port)
                _logger.LogInformation($"Network port changed from {oldSettings.Network.Port} to {newSettings.Network.Port}");

            if (oldSettings.Security.RequireEncryption != newSettings.Security.RequireEncryption)
                _logger.LogWarning($"Encryption requirement changed from {oldSettings.Security.RequireEncryption} to {newSettings.Security.RequireEncryption}");

            if (oldSettings.Stream.TargetFps != newSettings.Stream.TargetFps)
                _logger.LogInformation($"Target FPS changed from {oldSettings.Stream.TargetFps} to {newSettings.Stream.TargetFps}");
        }

        private void ValidateConfiguration(object? state)
        {
            try
            {
                _currentSettings?.Validate();
                _logger.LogDebug("Periodic configuration validation successful");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Periodic configuration validation failed");
                ConfigurationError?.Invoke(this, ex);
            }
        }

        public void SaveConfiguration()
        {
            if (_currentSettings == null)
                throw new InvalidOperationException("No configuration loaded");

            try
            {
                string jsonContent = _currentSettings.ToJson();
                File.WriteAllText(_configPath, jsonContent);
                _logger.LogInformation("Configuration saved successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save configuration");
                throw;
            }
        }

        public void UpdateConfiguration(Action<AppSettings> updateAction)
        {
            if (_currentSettings == null)
                throw new InvalidOperationException("No configuration loaded");

            try
            {
                updateAction(_currentSettings);
                _currentSettings.Validate();
                SaveConfiguration();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update configuration");
                throw;
            }
        }

        public void Dispose()
        {
            _watcher.Dispose();
            _reloadLock.Dispose();
            _validationTimer.Dispose();
        }
    }
}

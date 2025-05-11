using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using RemoteDesktopCommon.Config;
using RemoteDesktopCommon.Protocol;
using RemoteDesktopCommon.Security;

namespace RemoteDesktopServer
{
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            var serviceCollection = new ServiceCollection();
            ConfigureServices(serviceCollection);

            var serviceProvider = serviceCollection.BuildServiceProvider();

            var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("RemoteDesktopServer starting...");

            try
            {
                var configWatcher = serviceProvider.GetRequiredService<ConfigWatcher>();
                configWatcher.ConfigurationChanged += (s, e) =>
                {
                    logger.LogInformation("Configuration updated.");
                };

                var reliableUdp = serviceProvider.GetRequiredService<ReliableUdpProtocol>();
                await reliableUdp.StartServer(ProtocolConstants.DEFAULT_PORT);

                logger.LogInformation($"Server is running on port {ProtocolConstants.DEFAULT_PORT}. Press Ctrl+C to exit.");

                // Handle graceful shutdown
                var tcs = new TaskCompletionSource();
                Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    tcs.SetResult();
                };

                await tcs.Task;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while starting the server");
                throw;
            }
        }

        private static void ConfigureServices(IServiceCollection services)
        {
            // Add logging
            services.AddLogging(builder =>
            {
                builder.ClearProviders();
                builder.AddSimpleConsole(options =>
                {
                    options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss] ";
                    options.SingleLine = true;
                    options.UseUtcTimestamp = true;
                });
            });

            // Add configuration
            services.AddSingleton<ConfigWatcher>(provider =>
            {
                var logger = provider.GetRequiredService<ILogger<ConfigWatcher>>();
                return new ConfigWatcher(logger, "appsettings.json");
            });

            // Add network services
            services.AddSingleton<ReliableUdpProtocol>();

            // Add security services
            services.AddSingleton<AuthenticationManager>(provider =>
            {
                var logger = provider.GetRequiredService<ILogger<AuthenticationManager>>();
                var config = provider.GetRequiredService<ConfigWatcher>().CurrentSettings;
                return new AuthenticationManager(logger, config.Authentication.JwtSecret);
            });

            services.AddSingleton<EncryptionHelper>(provider =>
            {
                var logger = provider.GetRequiredService<ILogger<EncryptionHelper>>();
                var config = provider.GetRequiredService<ConfigWatcher>().CurrentSettings;
                return new EncryptionHelper(logger, config.Security.EncryptionKey);
            });
        }
    }
}

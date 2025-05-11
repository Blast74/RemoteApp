using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RemoteDesktopCommon.Config;
using RemoteDesktopCommon.Protocol;

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

            var configWatcher = serviceProvider.GetRequiredService<ConfigWatcher>();
            configWatcher.ConfigurationChanged += (s, e) =>
            {
                logger.LogInformation("Configuration updated.");
            };

            var reliableUdp = serviceProvider.GetRequiredService<ReliableUdpProtocol>();
            await reliableUdp.StartServer(8950);

            logger.LogInformation("Server is running. Press Ctrl+C to exit.");
            await Task.Delay(-1);
        }

        private static void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(configure => configure.AddConsole());
            services.AddSingleton<ConfigWatcher>(provider =>
            {
                var logger = provider.GetRequiredService<ILogger<ConfigWatcher>>();
                return new ConfigWatcher(logger, "appsettings.json");
            });
            services.AddSingleton<ReliableUdpProtocol>(provider =>
            {
                var logger = provider.GetRequiredService<ILogger<ReliableUdpProtocol>>();
                return new ReliableUdpProtocol(logger);
            });
        }
    }
}

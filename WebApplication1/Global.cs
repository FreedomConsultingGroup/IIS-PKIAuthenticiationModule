using log4net;
using log4net.Repository.Hierarchy;
using log4net.Core;
using log4net.Appender;
using log4net.Layout;
using log4net.Config;

[assembly: XmlConfigurator(ConfigFile = @"C:\inetpub\wwwroot\portal\Ownership\log4net.config", Watch = true)]

namespace FCG.PKIAuthentication
{
    public class Global
    {
        // Global variables used by different files, as well as things that may need to be changed by other users
        public const string RootDirectory = @"C:\inetpub\";

        public const string PortalUrl = @"https://fcg-arcgis-srv.freedom.local/portal/";

        private static ILog Log = null;
        
        public static void LogInfo(string message)
        {
            if(Log == null)
            {
                //LogSetup();
                Log = LogManager.GetLogger(typeof(Global));
                Log.Info("Logging started");
            }
            Log.Info(message);
        }

        // Set configuration for logging
        //public static void LogSetup()
        //{
        //    Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();

        //    PatternLayout pattern = new PatternLayout
        //    {
        //        ConversionPattern = "%date{MM-dd HH:mm} [%thread] %-5level %logger - %message%newline"
        //    };
        //    pattern.ActivateOptions();

        //    RollingFileAppender rfa = new RollingFileAppender
        //    {
        //        Layout = pattern,
        //        AppendToFile = true,
        //        File = @"C:\inetpub\logs\PKIAuth\PKIAuth.log",
        //        RollingStyle = RollingFileAppender.RollingMode.Composite,
        //        DatePattern = ".yyyy-MM-dd",
        //        MaxSizeRollBackups = 10,
        //        StaticLogFileName = true,
        //        MaximumFileSize = "1MB"
        //    };
        //    rfa.ActivateOptions();

        //    hierarchy.Root.AddAppender(rfa);

        //    hierarchy.Root.Level = Level.All;
        //    hierarchy.Configured = true;
        //}
    }
}
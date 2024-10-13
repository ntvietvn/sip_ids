/*config.c*/
/*
To compile : gcc -o config config.c -lconfig
To run     : ./config
*/

#include "config.h"
#include "tslog.h"

struct capture_t capture_cfg;
struct notif_t noti_cfg;
struct system_t system_cfg;
struct criteria_t criteria_cfg;

static int get_facility(const char *facility)
{
	if (!facility) return -1;
	if (!strcmp(facility, "LOG_LOCAL0"))
		return (16<<3);
	if (!strcmp(facility, "LOG_LOCAL1"))
		return (17<<3);
	if (!strcmp(facility, "LOG_LOCAL2"))
		return (18<<3);
	if (!strcmp(facility, "LOG_LOCAL3"))
		return (19<<3);
	if (!strcmp(facility, "LOG_LOCAL4"))
		return (20<<3);
	if (!strcmp(facility, "LOG_LOCAL5"))
		return (21<<3);
	if (!strcmp(facility, "LOG_LOCAL6"))
		return (22<<3);
	if (!strcmp(facility, "LOG_LOCAL7"))
		return (23<<3);
	return 0;
}

void load_config(const char *config_file_name)
{
    config_t cfg;               /*Returns all parameters in this structure */
    config_setting_t *setting;
    const char *str1, *str2, *str3, *str4,*email,*facility, *logfile, *ipds_srv_ip;

		memset(&capture_cfg,0, sizeof(struct capture_t));
		memset(&noti_cfg,0, sizeof(struct notif_t));
		memset(&system_cfg,0, sizeof(struct system_t));
		memset(&criteria_cfg,0, sizeof(struct criteria_t));

    /*Initialization */
    config_init(&cfg);
 
    /* Read the file. If there is an error, report it and exit. */
    if (!config_read_file(&cfg, config_file_name))
    {
        printf("\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return;
    }
 
    /* Get the configuration file name. */
    if (config_lookup_string(&cfg, "filename", &str1))
        printf("\nFile Type: %s", str1);
    else
        printf("\nNo 'filename' setting in configuration file.");
 
    /*Read the parameter group*/
    setting = config_lookup(&cfg, "capture");
    if (setting != NULL)
    {
        /*Read the string*/
        if (!config_setting_lookup_int(setting, "port", &capture_cfg.port))
        {
            printf("\nNo 'port' setting in configuration file.");
        }
 
        /*Read the integer*/
        if (!config_setting_lookup_string(setting, "interface", &str2))
        {
            printf("\nNo 'interface' setting in configuration file.");
        }
        else strncpy(capture_cfg.inf,str2, MAX_BUF -1);
        if (!config_setting_lookup_int(setting, "stateful", &capture_cfg.sf))
        {
            printf("\nNo 'stateful' setting in configuration file.");
        }
        if (!config_setting_lookup_string(setting, "whitelist", &str3))
        {
            printf("\nNo 'whitelist' setting in configuration file.");
        }
        else strncpy(capture_cfg.wl,str3,MAX_BUF - 1);
        if (!config_setting_lookup_string(setting, "blacklist", &str4))
        {
            printf("\nNo 'blacklist' setting in configuration file.");
        }
        else strncpy(capture_cfg.bl,str4,MAX_BUF - 1);
    }
    setting = config_lookup(&cfg, "system");
    if (setting != NULL)
    {
        /*Read the string*/
        if (!config_setting_lookup_int(setting, "nb_threads", &system_cfg.nb_threads))
        {
            printf("\nNo 'nb_threads' setting in configuration file.");
        }
        if (!config_setting_lookup_int(setting, "qsize", &system_cfg.qsize))
        {
            printf("\nNo 'qsize' setting in configuration file.");
        }
 
        if (!config_setting_lookup_int(setting, "maxbyte", &system_cfg.maxbyte))
        {
            printf("\nNo 'maxbyte' setting in configuration file.");
        }
        if (!config_setting_lookup_int(setting, "stack_size", &system_cfg.stack_size))
        {
            printf("\nNo 'stack_size' setting in configuration file.");
        }
        if (!config_setting_lookup_string(setting, "facility", &facility))
        {
            printf("\nNo 'email_list' setting in configuration file.");
        } else system_cfg.facility = get_facility(facility);
        if (!config_setting_lookup_string(setting, "logfile", &logfile))
        {
            printf("\nNo 'logfile' setting in configuration file.");
        }
        else strncpy(system_cfg.logfile,logfile,MAX_STR - 1);
    }
 
    /* notification */
		setting = config_lookup(&cfg, "notification");
    if (setting != NULL)
    {
        /*Read the integer*/
        if (!config_setting_lookup_string(setting, "email_list", &email))
        {
            printf("\nNo 'email_list' setting in configuration file.");
        }
        else strncpy(noti_cfg.email_list,email, MAX_STR -1);
        if (!config_setting_lookup_string(setting, "ipds_srv_ip", &ipds_srv_ip))
        {
            printf("\nNo 'ipds_srv_ip' setting in configuration file.");
        }
        else strncpy(noti_cfg.ipds_srv_ip,ipds_srv_ip, MAX_STR -1);
        if (!config_setting_lookup_int(setting, "ipds_srv_port", &noti_cfg.ipds_srv_port))
        {
            printf("\nNo 'ipds_srv_port' setting in configuration file.");
				}
        if (!config_setting_lookup_int(setting, "ipds_srv_sub_port", &noti_cfg.ipds_srv_sub_port))
        {
            printf("\nNo 'ipds_srv_sub_port' setting in configuration file.");
				}
    }
    setting = config_lookup(&cfg, "criteria");
    if (setting != NULL)
    {
        /*Read the string*/
        if (!config_setting_lookup_int(setting, "mean", &criteria_cfg.mean))
        {
            printf("\nNo 'criteria' setting in configuration file.");
        }
        if (!config_setting_lookup_int(setting, "nb_fail", &criteria_cfg.nb_fail))
        {
            printf("\nNo 'nb_fail' setting in configuration file.");
        }
 
        if (!config_setting_lookup_int(setting, "nb_hijack", &criteria_cfg.nb_hijack))
        {
            printf("\nNo 'nb_hijack' setting in configuration file.");
        }
    }
 
    config_destroy(&cfg);
}

void show_config()
{
		tslog_info("------------------");
		tslog_info("Config info");
		tslog_info("------------------");
		tslog_info("---- Config capture");
		tslog_info("port: %d", capture_cfg.port);
		tslog_info("stateful: %d", capture_cfg.sf);
		tslog_info("interface: %s", capture_cfg.inf);
		tslog_info("whitelist: %s", capture_cfg.wl);
		tslog_info("blacklist: %s", capture_cfg.bl);
		tslog_info("");
		tslog_info("---- Config notification");
		tslog_info("email_list: %s", noti_cfg.email_list);
		tslog_info("");
		tslog_info("---- Config system");
		tslog_info("nb_threads: %d", system_cfg.nb_threads);
		tslog_info("qsize: %d", system_cfg.qsize);
		tslog_info("maxbyte: %d", system_cfg.maxbyte);
		tslog_info("stack_size: %d", system_cfg.stack_size);
		tslog_info("logfile: %s", system_cfg.logfile);
		tslog_info("");
		tslog_info("---- Config criteria");
		tslog_info("mean: %d", criteria_cfg.mean);
		tslog_info("nb_fail: %d", criteria_cfg.nb_fail);
		tslog_info("nb_hijack: %d", criteria_cfg.nb_hijack);
		tslog_info("");
}

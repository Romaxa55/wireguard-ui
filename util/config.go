package util

import "strings"

// Runtime config
var (
	DisableLogin   bool
	BindAddress    string
	SmtpHostname   string
	SmtpPort       int
	SmtpUsername   string
	SmtpPassword   string
	SmtpNoTLSCheck bool
	SmtpEncryption string
	SmtpAuthType   string
	SendgridApiKey string
	MailgunApiKey  string
	MailgunDomain  string
	MailgunAPIBase string
	EmailFrom      string
	EmailFromName  string
	SessionSecret  []byte
	WgConfTemplate string
	BasePath       string
)

const (
	DefaultUsername                        = "admin"
	DefaultPassword                        = "admin"
	DefaultIsAdmin                         = true
	DefaultServerAddress                   = "10.252.1.0/24"
	DefaultServerPort                      = 51820
	DefaultDNS                             = "1.1.1.1"
	DefaultMTU                             = 1450
	DefaultPersistentKeepalive             = 15
	DefaultFirewallMark                    = "0xca6c" // i.e. 51820
	DefaultTable                           = "auto"
	DefaultConfigFilePath                  = "/etc/wireguard/wg0.conf"
	DefaultRemoteAPI                       = "http://127.0.0.1:1234"
	DefaultTelegramChat                    = -1001866387689
	EnvTelegramChat                        = "WGUI_TELEGRAM_CHAT"
	EnvTelegramToken                       = "WGUI_TELEGRAM_TOKEN"
	DefaultTelegramToken                   = "bot"
	UsernameEnvVar                         = "WGUI_USERNAME"
	PasswordEnvVar                         = "WGUI_PASSWORD"
	PasswordHashEnvVar                     = "WGUI_PASSWORD_HASH"
	FaviconFilePathEnvVar                  = "WGUI_FAVICON_FILE_PATH"
	EndpointAddressEnvVar                  = "WGUI_ENDPOINT_ADDRESS"
	DNSEnvVar                              = "WGUI_DNS"
	MTUEnvVar                              = "WGUI_MTU"
	PersistentKeepaliveEnvVar              = "WGUI_PERSISTENT_KEEPALIVE"
	FirewallMarkEnvVar                     = "WGUI_FIREWALL_MARK"
	TableEnvVar                            = "WGUI_TABLE"
	ConfigFilePathEnvVar                   = "WGUI_CONFIG_FILE_PATH"
	ConfigRemoteAPIEnvVar                  = "WGUI_CONFIG_RemoteAPI"
	LogLevel                               = "WGUI_LOG_LEVEL"
	ServerAddressesEnvVar                  = "WGUI_SERVER_INTERFACE_ADDRESSES"
	ServerListenPortEnvVar                 = "WGUI_SERVER_LISTEN_PORT"
	ServerPostUpScriptEnvVar               = "WGUI_SERVER_POST_UP_SCRIPT"
	ServerPostDownScriptEnvVar             = "WGUI_SERVER_POST_DOWN_SCRIPT"
	DefaultClientAllowedIpsEnvVar          = "WGUI_DEFAULT_CLIENT_ALLOWED_IPS"
	DefaultClientExtraAllowedIpsEnvVar     = "WGUI_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS"
	DefaultClientUseServerDNSEnvVar        = "WGUI_DEFAULT_CLIENT_USE_SERVER_DNS"
	DefaultClientEnableAfterCreationEnvVar = "WGUI_DEFAULT_CLIENT_ENABLE_AFTER_CREATION"
	CronEnvVar                             = "WGUI_SCHEDULER_CRON"
)

func ParseBasePath(basePath string) string {
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if strings.HasSuffix(basePath, "/") {
		basePath = strings.TrimSuffix(basePath, "/")
	}
	return basePath
}

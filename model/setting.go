package model

import (
	"time"
)

// GlobalSetting model
type GlobalSetting struct {
	EndpointAddress     string    `json:"endpoint_address"`
	DNSServers          []string  `json:"dns_servers"`
	MTU                 int       `json:"mtu,string"`
	PersistentKeepalive int       `json:"persistent_keepalive,string"`
	FirewallMark        string    `json:"firewall_mark"`
	Table               string    `json:"table"`
	ConfigFilePath      string    `json:"config_file_path"`
	RemoteAPI           string    `json:"remote_api"`
	UpdatedAt           time.Time `json:"updated_at"`
}

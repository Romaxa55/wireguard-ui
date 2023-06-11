package model

import "time"

type Peer struct {
	PublicKey       string    `json:"public_key"`
	HasPresharedKey bool      `json:"has_preshared_key"`
	Endpoint        string    `json:"endpoint"`
	LastHandshake   time.Time `json:"last_handshake"`
	ReceiveBytes    int64     `json:"receive_bytes"`
	TransmitBytes   int64     `json:"transmit_bytes"`
	AllowedIPs      []string  `json:"allowed_ips"`
	ProtocolVersion int       `json:"protocol_version"`
}

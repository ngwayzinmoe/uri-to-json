package parser

// StreamField contains all possible transport and security settings.
// It is designed to be shared across all protocol parsers.
type StreamField struct {
	// Network & Transport
	Network        string `json:"network"`         // tcp, ws, grpc, h2, quic, udp
	StreamSecurity string `json:"stream_security"` // tls, reality, none

	// TLS / SNI Settings
	ServerName       string `json:"server_name"`        // SNI (Server Name Indication)
	TLSAllowInsecure string `json:"tls_allow_insecure"` // "true" or "false"
	TLSALPN          string `json:"tls_alpn"`           // h2, http/1.1
	Fingerprint      string `json:"fingerprint"`        // chrome, firefox, safari, edge, ios, etc.

	// WebSocket (WS) Settings
	Path string `json:"path"` // WebSocket path (e.g., /graphql)
	Host string `json:"host"` // Host header for WS/HTTP

	// gRPC Settings
	GRPCServiceName string `json:"grpc_service_name"`
	GRPCMultiMode   string `json:"grpc_multi_mode"` // "multi" or empty

	// REALITY Settings
	RealityPublicKey string `json:"reality_public_key"`
	RealityShortId   string `json:"reality_short_id"`
	RealitySpiderX   string `json:"reality_spider_x"`

	// TCP Header Type
	TCPHeaderType string `json:"tcp_header_type"` // "http" or "none"

	// Xray Specific (VLESS/Trojan)
	PacketEncoding string `json:"packet_encoding"` // xudp, none

	// Shadowsocks / UDP Specific
	UoT bool `json:"uot"` // UDP over TCP (version 2)

	// Sing-box Specific (WebSocket/QUIC Early Data)
	MaxEarlyData    int    `json:"max_early_data"`
	EarlyDataHeader string `json:"early_data_header"` // Sec-WebSocket-Protocol
}

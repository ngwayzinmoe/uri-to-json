package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Hysteria2Config represents a Hysteria2 server configuration
type Hysteria2Config struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Auth     string `json:"auth"`
	SNI      string `json:"sni,omitempty"`
	Insecure bool   `json:"insecure"`
	OBFS     string `json:"obfs,omitempty"`
	OBFSPass string `json:"obfs_password,omitempty"`
	Remark   string `json:"remark,omitempty"`
}

// ParserHysteria2 parses hysteria:// URIs
type ParserHysteria2 struct {
	Config      Hysteria2Config
	StreamField *StreamField // for outbound use
}

// Parse parses a hysteria:// URI into Hysteria2Config
func (p *ParserHysteria2) Parse(rawUri string) error {
	if !strings.HasPrefix(rawUri, "hysteria://") {
		return fmt.Errorf("invalid hysteria URI")
	}

	// remove scheme
	rawUri = strings.TrimPrefix(rawUri, "hysteria://")

	// split fragment (#...)
	remark := ""
	if idx := strings.Index(rawUri, "#"); idx != -1 {
		remark, _ = url.QueryUnescape(rawUri[idx+1:])
		rawUri = rawUri[:idx]
	}

	// parse query
	var queryStr string
	if idx := strings.Index(rawUri, "?"); idx != -1 {
		queryStr = rawUri[idx+1:]
		rawUri = rawUri[:idx]
	}

	// parse user info and host:port
	userHost := strings.SplitN(rawUri, "@", 2)
	if len(userHost) != 2 {
		return fmt.Errorf("invalid hysteria URI, missing auth or host")
	}

	auth := userHost[0]
	hostPort := userHost[1]

	host, portStr, err := netSplitHostPort(hostPort)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}

	// parse query parameters
	qValues, _ := url.ParseQuery(queryStr)
	insecure := qValues.Get("insecure") == "1" || qValues.Get("allow_insecure") == "1"

	p.Config = Hysteria2Config{
		Server:   host,
		Port:     port,
		Auth:     auth,
		SNI:      qValues.Get("sni"),
		Insecure: insecure,
		OBFS:     qValues.Get("obfs"),
		OBFSPass: qValues.Get("obfs-password"),
		Remark:   remark,
	}

	// StreamField setup
	p.StreamField = &StreamField{
		Network:          "udp",
		StreamSecurity:   "tls",
		ServerName:       p.Config.SNI,
		TLSAllowInsecure: insecure,
	}

	return nil
}

// GetAddr returns server address
func (p *ParserHysteria2) GetAddr() string {
	return p.Config.Server
}

// GetPort returns server port
func (p *ParserHysteria2) GetPort() int {
	return p.Config.Port
}

// ShowJSON prints Hysteria2Config in JSON
func (p *ParserHysteria2) ShowJSON() {
	data, _ := json.MarshalIndent(p.Config, "", "  ")
	fmt.Println(string(data))
}

// Helper function to split host:port safely
func netSplitHostPort(hostport string) (host, port string, err error) {
	parts := strings.Split(hostport, ":")
	if len(parts) < 2 {
		err = fmt.Errorf("invalid host:port")
		return
	}
	host = strings.Join(parts[:len(parts)-1], ":")
	port = parts[len(parts)-1]
	return
}

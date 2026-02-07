package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type Hysteria2Config struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Auth     string `json:"auth"`
	SNI      string `json:"sni"`
	Insecure bool   `json:"insecure"`
	OBFS     string `json:"obfs,omitempty"`
	OBFSPass string `json:"obfs_password,omitempty"`
	UpMbps   int    `json:"up_mbps,omitempty"`
	DownMbps int    `json:"down_mbps,omitempty"`
	Remark   string `json:"remark,omitempty"`
}

type ParserHysteria2 struct {
	Config      Hysteria2Config
	StreamField *StreamField
}

func (p *ParserHysteria2) Parse(rawUri string) string {
	u, err := url.Parse(rawUri)
	if err != nil {
		return ""
	}

	// Remark/Tag parsing
	remark := u.Fragment
	if remark != "" {
		if decoded, err := url.QueryUnescape(remark); err == nil {
			remark = decoded
		}
	}

	port, _ := strconv.Atoi(u.Port())
	query := u.Query()

	// Insecure logic
	insVal := strings.ToLower(query.Get("insecure"))
	allowIns := strings.ToLower(query.Get("allow_insecure"))
	insecure := insVal == "1" || insVal == "true" || allowIns == "1" || allowIns == "true"

	// BDP/Bandwidth logic
	up, _ := strconv.Atoi(query.Get("upmbps"))
	down, _ := strconv.Atoi(query.Get("downmbps"))

	p.Config = Hysteria2Config{
		Server:   u.Hostname(),
		Port:     port,
		Auth:     u.User.Username(),
		SNI:      query.Get("sni"),
		Insecure: insecure,
		OBFS:     query.Get("obfs"),
		OBFSPass: query.Get("obfs-password"),
		UpMbps:   up,
		DownMbps: down,
		Remark:   remark,
	}

	// StreamField mapping for general outbound use
	p.StreamField = &StreamField{
		Network:          "udp",
		StreamSecurity:   "tls",
		ServerName:       p.Config.SNI,
		TLSAllowInsecure: strconv.FormatBool(insecure),
	}

	jsonData, _ := json.MarshalIndent(p.Config, "", "  ")
	return string(jsonData)
}

func (p *ParserHysteria2) GetAddr() string { return p.Config.Server }
func (p *ParserHysteria2) GetPort() int    { return p.Config.Port }

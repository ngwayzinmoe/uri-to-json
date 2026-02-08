package xray

import (
	"fmt"
	"strings"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
)

var XrayOutboundTemplate = `{
  "protocol": "shadowsocks",
  "settings": %s,
  "streamSettings": %s,
  "tag": "proxy"
}`

var XraySSSettings = `{
  "servers": [
    {
      "address": "",
      "port": 0,
      "method": "",
      "password": "",
      "uot": true,
      "UoTVersion": 2
    }
  ]
}`

type ShadowSocksOut struct {
	Parser *parser.ParserSS
}

func (s *ShadowSocksOut) Parse(uri string) {
	s.Parser = &parser.ParserSS{}
	s.Parser.Parse(uri)
}

func (s *ShadowSocksOut) Build() string {
	p := s.Parser
	if p == nil || p.Address == "" {
		return ""
	}

	// settings
	set := gjson.New(XraySSSettings)
	set.Set("servers.0.address", p.Address)
	set.Set("servers.0.port", p.Port)
	set.Set("servers.0.method", p.Method)
	set.Set("servers.0.password", p.Password)

	// stream
	stream := buildStream(p.StreamField)

	return fmt.Sprintf(
		XrayOutboundTemplate,
		set.MustToJsonString(),
		stream,
	)
}

func buildStream(sf *parser.StreamField) string {
	j := gjson.New(`{"network":"tcp","security":"none"}`)
	j.Set("network", sf.Network)
	j.Set("security", sf.StreamSecurity)

	switch sf.Network {
	case "ws":
		j.Set("wsSettings.path", sf.Path)
		j.Set("wsSettings.headers.Host", sf.Host)
	case "grpc":
		j.Set("grpcSettings.serviceName", sf.GRPCServiceName)
		j.Set("grpcSettings.multiMode", sf.GRPCMultiMode == "multi")
	case "tcp":
		if sf.TCPHeaderType == "http" {
			j.Set("tcpSettings.header.type", "http")
			j.Set("tcpSettings.header.request.headers.Host", []string{sf.Host})
		}
	}

	if sf.StreamSecurity == "tls" {
		j.Set("tlsSettings.serverName", sf.ServerName)
		j.Set("tlsSettings.allowInsecure", sf.TLSAllowInsecure == "true")
		if sf.TLSALPN != "" {
			j.Set("tlsSettings.alpn", strings.Split(sf.TLSALPN, ","))
		}
	}

	return j.MustToJsonString()
}

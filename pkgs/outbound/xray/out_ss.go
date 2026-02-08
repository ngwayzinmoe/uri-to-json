package xray

import (
	"fmt"
	"strings"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
)

/*
Xray Shadowsocks outbound (official style)

https://xtls.github.io/config/outbounds/shadowsocks.html
*/

var XraySS = `{
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

// Xray outbound template (project original style)
var XrayOut = `{
	"protocol": "",
	"settings": %s,
	"streamSettings": %s,
	"tag": ""
}`

type ShadowSocksOut struct {
	RawUri   string
	Parser   *parser.ParserSS
	outbound string
}

/* ---------------- Parse ---------------- */

func (s *ShadowSocksOut) Parse(rawUri string) {
	s.RawUri = rawUri
	s.Parser = &parser.ParserSS{}
	_ = s.Parser.Parse(rawUri)

	// IMPORTANT: build stream from plugin
	s.Parser.BuildStream()
}

/* ---------------- Basic getters ---------------- */

func (s *ShadowSocksOut) Addr() string {
	if s.Parser == nil {
		return ""
	}
	return s.Parser.Address
}

func (s *ShadowSocksOut) Port() int {
	if s.Parser == nil {
		return 0
	}
	return s.Parser.Port
}

func (s *ShadowSocksOut) Scheme() string {
	return parser.SchemeSS
}

func (s *ShadowSocksOut) GetRawUri() string {
	return s.RawUri
}

/* ---------------- Settings ---------------- */

func (s *ShadowSocksOut) getSettings() string {
	if s.Parser == nil {
		return ""
	}

	j := gjson.New(XraySS)

	j.Set("servers.0.address", s.Parser.Address)
	j.Set("servers.0.port", s.Parser.Port)
	j.Set("servers.0.method", s.Parser.Method)
	j.Set("servers.0.password", s.Parser.Password)

	// UDP over TCP (recommended by Xray)
	j.Set("servers.0.uot", true)
	j.Set("servers.0.UoTVersion", 2)

	return j.MustToJsonString()
}

/* ---------------- StreamSettings ---------------- */

func buildStreamSettings(sf *parser.StreamField) string {
	if sf == nil || sf.Network == "" {
		return ""
	}

	j := gjson.New("{}")

	j.Set("network", sf.Network)

	if sf.StreamSecurity != "" {
		j.Set("security", sf.StreamSecurity)
	}

	switch sf.Network {

	case "tcp":
		if sf.TCPHeaderType != "" {
			j.Set("tcpSettings.header.type", sf.TCPHeaderType)

			if sf.Host != "" {
				j.Set(
					"tcpSettings.header.request.headers.Host",
					[]string{sf.Host},
				)
			}
		}

	case "ws":
		if sf.Path != "" {
			j.Set("wsSettings.path", sf.Path)
		}
		if sf.Host != "" {
			j.Set("wsSettings.headers.Host", sf.Host)
		}

	case "grpc":
		j.Set("grpcSettings.serviceName", sf.GRPCServiceName)
		j.Set("grpcSettings.multiMode", sf.GRPCMultiMode == "true")
	}

	if sf.StreamSecurity == "tls" {
		j.Set("tlsSettings.serverName", sf.ServerName)
		j.Set("tlsSettings.allowInsecure", sf.TLSAllowInsecure == "true")

		if sf.TLSALPN != "" {
			j.Set("tlsSettings.alpn",
				strings.Split(sf.TLSALPN, ","))
		}

		if sf.Fingerprint != "" {
			j.Set("tlsSettings.fingerprint", sf.Fingerprint)
		}
	}

	return j.MustToJsonString()
}

/* ---------------- Outbound builder ---------------- */

func (s *ShadowSocksOut) setProtocolAndTag(outStr string) string {
	j := gjson.New(outStr)
	j.Set("protocol", "shadowsocks")
	j.Set("tag", utils.OutboundTag)
	return j.MustToJsonString()
}

func (s *ShadowSocksOut) GetOutboundStr() string {
	if s.Parser == nil {
		return ""
	}

	// invalid ss
	if s.Parser.Address == "" || s.Parser.Port <= 0 {
		return ""
	}

	if s.outbound != "" {
		return s.outbound
	}

	settings := s.getSettings()

	stream := ""
	if s.Parser.StreamField != nil &&
		s.Parser.StreamField.Network != "" {
		stream = buildStreamSettings(s.Parser.StreamField)
	}

	outStr := fmt.Sprintf(XrayOut, settings, stream)

	s.outbound = s.setProtocolAndTag(outStr)
	return s.outbound
}

/* ---------------- Test ---------------- */

func TestSS() {
	rawUri := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0cGFzcw==@1.2.3.4:443?plugin=v2ray-plugin;tls;host=cdn.example.com;path=/ws#SS"

	sso := &ShadowSocksOut{}
	sso.Parse(rawUri)

	out := sso.GetOutboundStr()
	if out == "" {
		fmt.Println("invalid ss outbound")
		return
	}

	j := gjson.New(out)
	fmt.Println(j.MustToJsonIndentString())
}


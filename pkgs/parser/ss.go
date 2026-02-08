package sing

import (
	"fmt"
	"strings"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

var SingSS = `{
  "type": "shadowsocks",
  "tag": "ss-out",
  "server": "",
  "server_port": 0,
  "method": "",
  "password": ""
}`

type SShadowSocksOut struct {
	RawUri   string
	Parser   *parser.ParserSS
	outbound string
}

func (s *SShadowSocksOut) Parse(rawUri string) {
	s.RawUri = rawUri
	s.Parser = &parser.ParserSS{}
	_ = s.Parser.Parse(rawUri)
}

func (s *SShadowSocksOut) getSettings() string {
	p := s.Parser
	if p == nil || p.Address == "" || p.Port == 0 {
		return ""
	}

	j := gjson.New(SingSS)

	// ===== Required =====
	j.Set("type", "shadowsocks")
	j.Set("tag", utils.OutboundTag)
	j.Set("server", p.Address)
	j.Set("server_port", p.Port)
	j.Set("method", p.Method)
	j.Set("password", p.Password)

	// ===== Plugin =====
	if p.Plugin != "" {
		j.Set("plugin", p.Plugin)
	}

	// ===== Plugin opts =====
	opts := []string{}

	// obfs-local
	if p.OBFS != "" {
		opts = append(opts, fmt.Sprintf("obfs=%s", p.OBFS))
	}
	if p.OBFSHost != "" {
		opts = append(opts, fmt.Sprintf("obfs-host=%s", p.OBFSHost))
	}

	// v2ray-plugin mode
	if p.Mode != "" {
		opts = append(opts, fmt.Sprintf("mode=%s", p.Mode))
	}

	if len(opts) > 0 {
		j.Set("plugin_opts", strings.Join(opts, ";"))
	}

	// ===== Network =====
	if p.Network != "" {
		j.Set("network", p.Network) // tcp / udp
	}

	// ===== UDP over TCP =====
	if p.UoT {
		j.Set("udp_over_tcp", gjson.New(`{}`).Map())
	}

	// ===== Multiplex (optional default empty) =====
	if p.Mux {
		j.Set("multiplex", gjson.New(`{}`).Map())
	}

	return j.MustToJsonString()
}

func (s *SShadowSocksOut) GetOutboundStr() string {
	if s.outbound != "" {
		return s.outbound
	}
	settings := s.getSettings()
	if settings == "" {
		return ""
	}
	s.outbound = settings
	return s.outbound
}

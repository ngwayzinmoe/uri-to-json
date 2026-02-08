package sing

import (
	"fmt"
	"strings"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

/*
Sing-box Shadowsocks Outbound

Official doc: http://sing-box.sagernet.org/zh/configuration/outbound/shadowsocks/
*/

var SingSSTemplate = `{
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

/* ---------------- Parse ---------------- */

func (s *SShadowSocksOut) Parse(rawUri string) {
	s.RawUri = rawUri
	s.Parser = &parser.ParserSS{}
	_ = s.Parser.Parse(rawUri)

	// Build StreamField if plugin exists
	if s.Parser != nil {
		s.Parser.BuildStream()
	}
}

/* ---------------- Build JSON ---------------- */

func (s *SShadowSocksOut) getSettings() string {
	p := s.Parser
	if p == nil || p.Address == "" || p.Port == 0 {
		return ""
	}

	j := gjson.New(SingSSTemplate)

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

	if p.OBFS != "" {
		opts = append(opts, fmt.Sprintf("obfs=%s", p.OBFS))
	}
	if p.OBFSHost != "" {
		opts = append(opts, fmt.Sprintf("obfs-host=%s", p.OBFSHost))
	}
	if p.Mode != "" {
		opts = append(opts, fmt.Sprintf("mode=%s", p.Mode))
	}

	if len(opts) > 0 {
		j.Set("plugin_opts", strings.Join(opts, ";"))
	}

	// ===== Network =====
	if p.StreamField != nil && p.StreamField.Network != "" {
		j.Set("network", p.StreamField.Network)
	} else {
		j.Set("network", "tcp") // default
	}

	// ===== UDP over TCP =====
	if p.StreamField != nil && p.StreamField.UoT {
		j.Set("udp_over_tcp", gjson.New(`{}`).Map())
	}

	// ===== Multiplex (optional) =====
	if p.StreamField != nil && p.StreamField.Mux == "true" {
		j.Set("multiplex", gjson.New(`{}`).Map())
	}

	return j.MustToJsonString()
}

/* ---------------- Outbound String ---------------- */

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

/* ---------------- Test ---------------- */

func TestSS() {
	rawUri := "ss://chacha20-ietf-poly1305:pass@1.2.3.4:443?plugin=obfs-local&obfs=tls&obfs-host=cdn.example.com"
	sso := &SShadowSocksOut{}
	sso.Parse(rawUri)

	out := sso.GetOutboundStr()
	if out == "" {
		fmt.Println("invalid ss outbound")
		return
	}

	j := gjson.New(out)
	fmt.Println(j.MustToJsonIndentString())
	fmt.Println(out)
}


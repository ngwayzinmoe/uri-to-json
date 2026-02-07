package sing

import (
	"fmt"
	"strings"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
)

// Sing-box Shadowsocks template
var SingSS = `{
	"type": "shadowsocks",
	"tag": "ss-out",
	"server": "127.0.0.1",
	"server_port": 1080,
	"method": "2022-blake3-aes-128-gcm",
	"password": ""
}`

// SShadowSocksOut represents a parsed SS outbound for Sing-box
type SShadowSocksOut struct {
	RawUri   string
	Parser   *parser.ParserSS
	outbound string
}

// Parse parses raw ss:// URI
func (s *SShadowSocksOut) Parse(rawUri string) {
	s.RawUri = rawUri
	s.Parser = &parser.ParserSS{}
	_ = s.Parser.Parse(rawUri) // silent fail
}

// Addr returns server address
func (s *SShadowSocksOut) Addr() string {
	if s.Parser == nil {
		return ""
	}
	return s.Parser.Address
}

// Port returns server port
func (s *SShadowSocksOut) Port() int {
	if s.Parser == nil {
		return 0
	}
	return s.Parser.Port
}

// Scheme returns "ss"
func (s *SShadowSocksOut) Scheme() string {
	return parser.SchemeSS
}

// GetRawUri returns original ss:// URI
func (s *SShadowSocksOut) GetRawUri() string {
	return s.RawUri
}

// getSettings builds the Sing-box Shadowsocks outbound JSON
func (s *SShadowSocksOut) getSettings() string {
	if s.Parser == nil || s.Parser.Address == "" || s.Parser.Port == 0 {
		return "{}"
	}

	j := gjson.New(SingSS)

	j.Set("type", "shadowsocks")
	j.Set("server", s.Parser.Address)
	j.Set("server_port", s.Parser.Port)
	j.Set("method", s.Parser.Method)
	j.Set("password", s.Parser.Password)
	j.Set("tag", utils.OutboundTag)

	// UDP network + UDP over TCP
	j.Set("network", "udp")
	j.Set("udp_over_tcp", map[string]interface{}{
		"enabled": true,
		"version": 2,
	})

	// Optional plugin
	if s.Parser.Plugin != "" {
		j.Set("plugin", s.Parser.Plugin)
	}

	// Optional obfs plugin options
	var pluginOpts []string
	if s.Parser.OBFS != "" && s.Parser.OBFSHost != "" {
		pluginOpts = append(pluginOpts, fmt.Sprintf("obfs=%s", s.Parser.OBFS))
		pluginOpts = append(pluginOpts, fmt.Sprintf("obfs-host=%s", s.Parser.OBFSHost))
	}

	if s.Parser.Mode != "" {
		pluginOpts = append(pluginOpts, fmt.Sprintf("mode=%s", s.Parser.Mode))
	}

	if len(pluginOpts) > 0 {
		j.Set("plugin_opts", strings.Join(pluginOpts, ";"))
	}

	return j.MustToJsonString()
}

// GetOutboundStr returns finalized Sing-box outbound JSON string
func (s *SShadowSocksOut) GetOutboundStr() string {
	if s.outbound != "" {
		return s.outbound
	}

	settings := s.getSettings()
	if settings == "{}" {
		return ""
	}

	cnf := gjson.New(settings)
	s.outbound = cnf.MustToJsonString()
	return s.outbound
}

// TestSS demonstrates usage
func TestSS() {
	rawUri := "ss://chacha20-ietf-poly1305:t0srmdxrm3xyjnvqz9ewlxb2myq7rjuv@4e168c3.h4.gladns.com:2377/?plugin=obfs-local&obfs=tls&obfs-host=(TG@WangCai_1)a83679f:53325#TestChannel"
	sso := &SShadowSocksOut{}
	sso.Parse(rawUri)

	out := sso.GetOutboundStr()
	if out == "" {
		fmt.Println("Invalid SS URI")
		return
	}

	j := gjson.New(out)
	fmt.Println(j.MustToJsonIndentString())
	fmt.Println(out)
}

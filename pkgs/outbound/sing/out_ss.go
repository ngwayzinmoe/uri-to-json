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
func (that *SShadowSocksOut) Parse(rawUri string) {
	that.RawUri = rawUri
	that.Parser = &parser.ParserSS{}
	that.Parser.Parse(rawUri)
}

// Addr returns the server address
func (that *SShadowSocksOut) Addr() string {
	if that.Parser == nil { return "" }
	return that.Parser.Address
}

// Port returns the server port
func (that *SShadowSocksOut) Port() int {
	if that.Parser == nil { return 0 }
	return that.Parser.Port
}

// Scheme returns the protocol scheme
func (that *SShadowSocksOut) Scheme() string {
	return parser.SchemeSS
}

// GetRawUri returns the original URI
func (that *SShadowSocksOut) GetRawUri() string {
	return that.RawUri
}


func (that *SShadowSocksOut) GetOutboundStr() string {
	if that.Parser.Address == "" { return "" }

	if that.outbound == "" {
		j := gjson.New("{}")
		j.Set("type", "shadowsocks")
		j.Set("tag", utils.OutboundTag)
		j.Set("server", that.Parser.Address)
		j.Set("server_port", that.Parser.Port)
		j.Set("method", that.Parser.Method)
		j.Set("password", that.Parser.Password)
		j.Set("network", "udp") // UDP packets support

		// [UoT for Sing-box]
		if that.Parser.StreamField.UoT {
			j.Set("udp_over_tcp", map[string]interface{}{
				"enabled": true,
				"version": 2,
			})
		}

		// Plugin Options logic
		var pluginOpts []string
		if that.Parser.Plugin != "" {
			j.Set("plugin", that.Parser.Plugin)
			if that.Parser.OBFS != "" {
				pluginOpts = append(pluginOpts, fmt.Sprintf("obfs=%s", that.Parser.OBFS))
				pluginOpts = append(pluginOpts, fmt.Sprintf("obfs-host=%s", that.Parser.OBFSHost))
			}
			if that.Parser.Mode != "" {
				pluginOpts = append(pluginOpts, fmt.Sprintf("mode=%s", that.Parser.Mode))
			}
			if len(pluginOpts) > 0 {
				j.Set("plugin_opts", strings.Join(pluginOpts, ";"))
			}
		}

		// Final stream/transport settings
		PrepareStreamStr(j, that.Parser.StreamField)
		
		that.outbound = j.MustToJsonString()
	}
	return that.outbound
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

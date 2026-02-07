package sing

import (
	"fmt"
	"strings"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

type SShadowSocksOut struct {
	RawUri   string
	Parser   *parser.ParserSS
	outbound string
}

func (that *SShadowSocksOut) Parse(rawUri string) {
	that.RawUri = rawUri
	that.Parser = &parser.ParserSS{}
	that.Parser.Parse(rawUri)
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


func TestSS() {
	// rawUri := "ss://aes-256-gcm:bad5fba5-a7bc-4709-882b-e15edad16cef@ah-cmi-1000m.ikun666.club:18878#🇨🇳_CN_中国-\u003e🇸🇬_SG_新加坡"
	// rawUri := "ss://aes-128-gcm:g12sQi#ss#\u00261@183.232.170.32:20013?plugin=v2ray-plugin\u0026mode=websocket\u0026mux=undefined#🇨🇳_CN_中国-\u003e🇯🇵_JP_日本"
	rawUri := "ss://chacha20-ietf-poly1305:t0srmdxrm3xyjnvqz9ewlxb2myq7rjuv@4e168c3.h4.gladns.com:2377/?plugin=obfs-local\u0026obfs=tls\u0026obfs-host=(TG@WangCai_1)a83679f:53325#8DKJ|@Zyw_Channel"
	sso := &SShadowSocksOut{}
	sso.Parse(rawUri)
	o := sso.GetOutboundStr()
	j := gjson.New(o)
	fmt.Println(j.MustToJsonIndentString())
	fmt.Println(o)
}

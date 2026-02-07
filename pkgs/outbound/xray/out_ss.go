package xray

import (
	"fmt"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

type ShadowSocksOut struct {
	RawUri   string
	Parser   *parser.ParserSS
	outbound string
}

func (that *ShadowSocksOut) Parse(rawUri string) {
	that.RawUri = rawUri
	that.Parser = &parser.ParserSS{}
	that.Parser.Parse(rawUri)
}

func (that *ShadowSocksOut) GetOutboundStr() string {
	if that.Parser.Address == "" { return "" }
	
	if that.outbound == "" {
		// Servers Setting
		server := map[string]interface{}{
			"address":  that.Parser.Address,
			"port":     that.Parser.Port,
			"method":   that.Parser.Method,
			"password": that.Parser.Password,
		}
		
		// [UoT for Xray]
		if that.Parser.StreamField.UoT {
			server["uot"] = true
			server["UoTVersion"] = 2
		}

		j := gjson.New("{}")
		j.Set("protocol", "shadowsocks")
		j.Set("tag", utils.OutboundTag)
		j.Set("settings.servers", []interface{}{server})
		
		// Stream Settings
		stream := PrepareStreamString(that.Parser.StreamField)
		j.Set("streamSettings", gjson.New(stream).Map())
		
		that.outbound = j.MustToJsonString()
	}
	return that.outbound
}

func TestSS() {
	rawUri := "ss://aes-256-gcm:bad5fba5-a7bc-4709-882b-e15edad16cef@ah-cmi-1000m.ikun666.club:18878#🇨🇳_CN_中国-\u003e🇸🇬_SG_新加坡"
	// rawUri := "ss://aes-128-gcm:g12sQi#ss#\u00261@183.232.170.32:20013?plugin=v2ray-plugin\u0026mode=websocket\u0026mux=undefined#🇨🇳_CN_中国-\u003e🇯🇵_JP_日本"
	// rawUri := "ss://chacha20-ietf-poly1305:t0srmdxrm3xyjnvqz9ewlxb2myq7rjuv@4e168c3.h4.gladns.com:2377/?plugin=obfs-local\u0026obfs=tls\u0026obfs-host=(TG@WangCai_1)a83679f:53325#8DKJ|@Zyw_Channel"
	sso := &ShadowSocksOut{}
	sso.Parse(rawUri)
	o := sso.GetOutboundStr()
	j := gjson.New(o)
	fmt.Println(j.MustToJsonIndentString())
	fmt.Println(o)
}

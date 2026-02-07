package xray

import (
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
)

type Hysteria2Out struct {
	RawUri   string
	Parser   *parser.ParserHysteria2
	outbound string
}

func (that *Hysteria2Out) Parse(rawUri string) {
	that.RawUri = rawUri
	that.Parser = &parser.ParserHysteria2{}
	that.Parser.Parse(rawUri)
}

func (that *Hysteria2Out) GetOutboundStr() string {
	if that.Parser.Config.Server == "" {
		return ""
	}
	if that.outbound == "" {
		j := gjson.New("{}")
		j.Set("protocol", "hysteria2")
		j.Set("tag", utils.OutboundTag)

		// Settings section
		settings := map[string]interface{}{
			"server":   that.Parser.Config.Server,
			"port":     that.Parser.Config.Port,
			"auth":     that.Parser.Config.Auth,
		}
		if that.Parser.Config.OBFSPass != "" {
			settings["password"] = that.Parser.Config.OBFSPass
		}
		j.Set("settings", settings)

		// StreamSettings section
		stream := map[string]interface{}{
			"network": "udp",
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName":    that.Parser.Config.SNI,
				"allowInsecure": that.Parser.Config.Insecure,
			},
		}
		j.Set("streamSettings", stream)

		that.outbound = j.MustToJsonString()
	}
	return that.outbound
}

package sing

import (
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
)

type SHysteria2Out struct {
	RawUri   string
	Parser   *parser.ParserHysteria2
	outbound string
}

func (that *SHysteria2Out) Parse(rawUri string) {
	that.RawUri = rawUri
	that.Parser = &parser.ParserHysteria2{}
	that.Parser.Parse(rawUri)
}

func (that *SHysteria2Out) Addr() string { return that.Parser.GetAddr() }
func (that *SHysteria2Out) Port() int    { return that.Parser.GetPort() }

func (that *SHysteria2Out) GetOutboundStr() string {
	if that.Parser.Config.Server == "" {
		return ""
	}
	if that.outbound == "" {
		j := gjson.New("{}")
		j.Set("type", "hysteria2")
		j.Set("tag", utils.OutboundTag)
		j.Set("server", that.Parser.Config.Server)
		j.Set("server_port", that.Parser.Config.Port)
		j.Set("password", that.Parser.Config.Auth)

		// BDP (Bandwidth Control)
		if that.Parser.Config.UpMbps > 0 {
			j.Set("up_mbps", that.Parser.Config.UpMbps)
		}
		if that.Parser.Config.DownMbps > 0 {
			j.Set("down_mbps", that.Parser.Config.DownMbps)
		}

		// TLS Object
		tlsConf := map[string]interface{}{
			"enabled":     true,
			"server_name": that.Parser.Config.SNI,
			"insecure":    that.Parser.Config.Insecure,
		}
		j.Set("tls", tlsConf)

		// OBFS Object (Salamander support)
		if that.Parser.Config.OBFS != "" {
			obfsConf := map[string]interface{}{
				"type": that.Parser.Config.OBFS,
			}
			if that.Parser.Config.OBFSPass != "" {
				obfsConf["password"] = that.Parser.Config.OBFSPass
			}
			j.Set("obfs", obfsConf)
		}

		that.outbound = j.MustToJsonString()
	}
	return that.outbound
}

package sing

import (
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

/*
Sing-box Hysteria2 Configuration:
{
  "type": "hysteria2",
  "tag": "hysteria2-out",
  "server": "127.0.0.1",
  "server_port": 443,
  "password": "auth_password",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "insecure": false
  },
  "obfs": {
    "type": "salamander",
    "password": "obfs_password"
  }
}
*/

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

func (that *SHysteria2Out) Addr() string {
	return that.Parser.Config.Server
}

func (that *SHysteria2Out) Port() int {
	return that.Parser.Config.Port
}

func (that *SHysteria2Out) Scheme() string {
	return parser.SchemeHysteria2
}

func (that *SHysteria2Out) GetRawUri() string {
	return that.RawUri
}

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
		
		// Hysteria2 main password (auth)
		j.Set("password", that.Parser.Config.Auth)

		// TLS settings
		j.Set("tls.enabled", true)
		if that.Parser.Config.SNI != "" {
			j.Set("tls.server_name", that.Parser.Config.SNI)
		}
		if that.Parser.Config.Insecure {
			j.Set("tls.insecure", true)
		}

		// OBFS settings
		if that.Parser.Config.OBFS != "" {
			j.Set("obfs.type", that.Parser.Config.OBFS)
			if that.Parser.Config.OBFSPass != "" {
				j.Set("obfs.password", that.Parser.Config.OBFSPass)
			}
		}

		that.outbound = j.MustToJsonString()
	}
	return that.outbound
}


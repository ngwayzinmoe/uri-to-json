package xray

import (
	"fmt"
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

func (that *Hysteria2Out) Addr() string   { return that.Parser.GetAddr() }
func (that *Hysteria2Out) Port() int      { return that.Parser.GetPort() }
func (that *Hysteria2Out) Scheme() string { return parser.SchemeHysteria2 }

func (that *Hysteria2Out) GetOutboundStr() string {
	if that.Parser.Config.Server == "" {
		return ""
	}
	if that.outbound == "" {
		// Settings section
		setObj := gjson.New("{}")
		setObj.Set("server", that.Parser.Config.Server)
		setObj.Set("port", that.Parser.Config.Port)
		setObj.Set("auth", that.Parser.Config.Auth)
		if that.Parser.Config.OBFSPass != "" {
			setObj.Set("password", that.Parser.Config.OBFSPass)
		}

		// StreamSettings section
		streamObj := gjson.New(`{"network":"udp","security":"tls"}`)
		streamObj.Set("tlsSettings.serverName", that.Parser.Config.SNI)
		streamObj.Set("tlsSettings.allowInsecure", that.Parser.Config.Insecure)

		// Final Outbound
		out := gjson.New("{}")
		out.Set("protocol", "hysteria2")
		out.Set("tag", utils.OutboundTag)
		out.Set("settings", setObj.Map())
		out.Set("streamSettings", streamObj.Map())
		
		that.outbound = out.MustToJsonString()
	}
	return that.outbound
}

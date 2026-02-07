package xray

import (
	

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

// Template for Hysteria2 settings
var XrayHysteria2 = `{
	"server": "127.0.0.1",
	"port": 1234,
	"auth": "",
	"password": ""
}`

// Hysteria2Out represents a parsed Hysteria2 outbound
type Hysteria2Out struct {
	RawUri   string
	Parser   *parser.ParserHysteria2
	outbound string
}

// Parse parses the raw hysteria:// URI
func (that *Hysteria2Out) Parse(rawUri string) {
	that.RawUri = rawUri
	that.Parser = &parser.ParserHysteria2{}
	_ = that.Parser.Parse(rawUri)
}

func (that *Hysteria2Out) Addr() string {
	return that.Parser.Config.Server
}

func (that *Hysteria2Out) Port() int {
	return that.Parser.Config.Port
}

func (that *Hysteria2Out) Scheme() string {
	return parser.SchemeHysteria2
}

func (that *Hysteria2Out) GetRawUri() string {
	return that.RawUri
}

// getSettings returns the Hysteria2 server settings JSON
func (that *Hysteria2Out) getSettings() string {
	j := gjson.New(XrayHysteria2)
	j.Set("server", that.Parser.Config.Server)
	j.Set("port", that.Parser.Config.Port)
	j.Set("auth", that.Parser.Config.Auth)

	if that.Parser.Config.OBFSPass != "" {
		j.Set("password", that.Parser.Config.OBFSPass)
	}
	return j.MustToJsonString()
}

// GetOutboundStr builds the final Xray Hysteria2 outbound
func (that *Hysteria2Out) GetOutboundStr() string {
	if that.Parser.Config.Server == "" || that.Parser.Config.Port == 0 {
		return ""
	}

	if that.outbound != "" {
		return that.outbound
	}

	settings := that.getSettings()

	// Use Parser.StreamField if available
	stream := gjson.New(`{
		"network": "udp",
		"security": "tls",
		"tlsSettings": {
			"serverName": "",
			"allowInsecure": false
		}
	}`)

	if that.Parser.StreamField != nil {
		stream.Set("tlsSettings.serverName", that.Parser.StreamField.ServerName)
		stream.Set("tlsSettings.allowInsecure", that.Parser.StreamField.TLSAllowInsecure)
	}

	// Build final outbound object
	outObj := gjson.New("{}")
	outObj.Set("protocol", "hysteria2")
	outObj.Set("tag", utils.OutboundTag)
	outObj.Set("settings", gjson.New(settings))
	outObj.Set("streamSettings", stream)

	that.outbound = outObj.MustToJsonString()
	return that.outbound
}

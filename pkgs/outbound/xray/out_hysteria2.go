package xray

import (
	"fmt"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

/*
Hysteria2 Xray Configuration Structure:
{
  "protocol": "hysteria2",
  "settings": {
    "server": "1.2.3.4",
    "port": 1234,
    "auth": "your-uuid",
    "password": "your-password"
  },
  "streamSettings": {
    "network": "udp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "example.com",
      "allowInsecure": false
    }
  }
}
*/

var XrayHysteria2 string = `{
	"server": "127.0.0.1",
	"port": 1234,
	"auth": "",
	"password": ""
}`

type Hysteria2Out struct {
	RawUri   string
	Parser   *parser.ParserHysteria2
	outbound string
}

func (that *Hysteria2Out) Parse(rawUri string) {
	that.RawUri = rawUri
	that.Parser = &parser.ParserHysteria2{}
	// ရှေ့မှာပေးခဲ့တဲ့ ParserHysteria2 logic ကို သုံးထားပါတယ်
	that.Parser.Parse(rawUri) 
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

func (that *Hysteria2Out) getSettings() string {
	j := gjson.New(XrayHysteria2)
	j.Set("server", that.Parser.Config.Server)
	j.Set("port", that.Parser.Config.Port)
	// Hysteria2 မှာ auth field ကို သုံးပါတယ်
	j.Set("auth", that.Parser.Config.Auth)
	
	// အကယ်၍ obfs password ရှိရင် password field မှာ ထည့်ပေးရပါတယ်
	if that.Parser.Config.OBFSPass != "" {
		j.Set("password", that.Parser.Config.OBFSPass)
	}
	return j.MustToJsonString()
}

func (that *Hysteria2Out) GetOutboundStr() string {
	if that.Parser.Config.Server == "" && that.Parser.Config.Port == 0 {
		return ""
	}
	
	if that.outbound == "" {
		settings := that.getSettings()
		
		// Hysteria2 stream settings ကို manual တည်ဆောက်ခြင်း
		// Hysteria2 သည် standard QUIC/UDP သုံးသဖြင့် stream settings ကွဲပြားနိုင်သည်
		streamObj := gjson.New(`{
			"network": "udp",
			"security": "tls",
			"tlsSettings": {
				"serverName": "",
				"allowInsecure": false
			}
		}`)
		streamObj.Set("tlsSettings.serverName", that.Parser.Config.SNI)
		streamObj.Set("tlsSettings.allowInsecure", that.Parser.Config.Insecure)
		
		// XrayOut template ကို သုံးပြီး final outbound string ထုတ်မယ်
		outStr := fmt.Sprintf(XrayOut, settings, streamObj.MustToJsonString())
		
		// Protocol နဲ့ Tag သတ်မှတ်မယ်
		j := gjson.New(outStr)
		j.Set("protocol", "hysteria2")
		j.Set("tag", utils.OutboundTag)
		that.outbound = j.MustToJsonString()
	}
	return that.outbound
}

package xray

import (
	"fmt"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
)

/*
https://xtls.github.io/config/outbounds/shadowsocks.html#serverobject

{
	"servers": [
	  {
		"email": "love@xray.com",
		"address": "127.0.0.1",
		"port": 1234,
		"method": "加密方式",
		"password": "密码",
		"uot": true,
		"UoTVersion": 2,
		"level": 0
	  }
	]
}

Method:
2022-blake3-aes-128-gcm
2022-blake3-aes-256-gcm
2022-blake3-chacha20-poly1305
aes-256-gcm
aes-128-gcm
chacha20-poly1305 或称 chacha20-ietf-poly1305
xchacha20-poly1305 或称 xchacha20-ietf-poly1305
none 或 plain

UoTVersion:
UDP over TCP 的实现版本。
当前可选值：1, 2

*/

var XraySS = `{
	"servers": [
		{
			"address": "",
			"port": 0,
			"method": "",
			"password": "",
			"uot": true,
			"UoTVersion": 2
		}
	]
}`


type ShadowSocksOut struct {
	RawUri   string
	Parser   *parser.ParserSS
	outbound string
}

func (s *ShadowSocksOut) Parse(rawUri string) {
	s.RawUri = rawUri
	s.Parser = &parser.ParserSS{}
	_ = s.Parser.Parse(rawUri) // silent-fail handled later
}

func (s *ShadowSocksOut) Addr() string {
	if s.Parser == nil {
		return ""
	}
	return s.Parser.Address
}

func (s *ShadowSocksOut) Port() int {
	if s.Parser == nil {
		return 0
	}
	return s.Parser.Port
}

func (s *ShadowSocksOut) Scheme() string {
	return parser.SchemeSS
}

func (s *ShadowSocksOut) GetRawUri() string {
	return s.RawUri
}

func (s *ShadowSocksOut) getSettings() string {
	if s.Parser == nil {
		return ""
	}

	j := gjson.New(XraySS)

	j.Set("servers.0.address", s.Parser.Address)
	j.Set("servers.0.port", s.Parser.Port)
	j.Set("servers.0.method", s.Parser.Method)
	j.Set("servers.0.password", s.Parser.Password)

	// UDP over TCP (Xray recommended)
	j.Set("servers.0.uot", true)
	j.Set("servers.0.UoTVersion", 2)

	return j.MustToJsonString()
}


func (s *ShadowSocksOut) setProtocolAndTag(outStr string) string {
	j := gjson.New(outStr)
	j.Set("protocol", "shadowsocks")
	j.Set("tag", utils.OutboundTag)
	return j.MustToJsonString()
}

func (s *ShadowSocksOut) GetOutboundStr() string {
	if s.Parser == nil {
		return ""
	}

	// invalid ss
	if s.Parser.Address == "" || s.Parser.Port <= 0 {
		return ""
	}

	if s.outbound != "" {
		return s.outbound
	}

	settings := s.getSettings()

	// Shadowsocks does NOT use stream settings
	outStr := fmt.Sprintf(XrayOut, settings, "")

	s.outbound = s.setProtocolAndTag(outStr)
	return s.outbound
}

func TestSS() {
	rawUri := "ss://aes-256-gcm:bad5fba5-a7bc-4709-882b-e15edad16cef@ah-cmi-1000m.ikun666.club:18878#CN-SG"

	sso := &ShadowSocksOut{}
	sso.Parse(rawUri)

	out := sso.GetOutboundStr()
	if out == "" {
		fmt.Println("invalid ss outbound")
		return
	}

	j := gjson.New(out)
	fmt.Println(j.MustToJsonIndentString())
}


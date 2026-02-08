package sing

import (
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
)

type SShadowSocksOut struct {
	Parser *parser.ParserSS
}

func (s *SShadowSocksOut) Parse(uri string) {
	s.Parser = &parser.ParserSS{}
	s.Parser.Parse(uri)
}

func (s *SShadowSocksOut) Build() string {
	p := s.Parser
	if p == nil || p.Address == "" {
		return ""
	}

	j := gjson.New(`{
	  "type":"shadowsocks",
	  "tag":"proxy",
	  "server":"",
	  "server_port":0,
	  "method":"",
	  "password":""
	}`)

	j.Set("server", p.Address)
	j.Set("server_port", p.Port)
	j.Set("method", p.Method)
	j.Set("password", p.Password)

	if p.Network != "" {
		j.Set("network", p.Network)
	}

	if p.StreamSecurity == "tls" {
		j.Set("tls.enabled", true)
		j.Set("tls.server_name", p.ServerName)
		j.Set("tls.insecure", p.TLSAllowInsecure == "true")
	}

	return j.MustToJsonString()
}

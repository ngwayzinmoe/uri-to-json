package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

type Hysteria2Config struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Auth     string `json:"auth"`
	SNI      string `json:"sni"`
	Insecure bool   `json:"insecure"`
	OBFS     string `json:"obfs,omitempty"`
	OBFSPass string `json:"obfs_password,omitempty"`
	Remark   string `json:"remark,omitempty"`
}

type ParserHysteria2 struct {
	Config      Hysteria2Config
	StreamField *StreamField // [၁] StreamField Pointer ထည့်ပေးပါ (Outbound logic အတွက်)
}

func (p *ParserHysteria2) Parse(rawUri string) string {
	u, err := url.Parse(rawUri)
	if err != nil {
		return ""
	}

	remark := u.Fragment
	if remark != "" {
		if decodedRemark, err := url.QueryUnescape(remark); err == nil {
			remark = decodedRemark
		}
	}

	port, _ := strconv.Atoi(u.Port())
	query := u.Query()
	insecure := query.Get("insecure") == "1" || query.Get("allow_insecure") == "1"

	p.Config = Hysteria2Config{
		Server:   u.Hostname(),
		Port:     port,
		Auth:     u.User.Username(),
		SNI:      query.Get("sni"),
		Insecure: insecure,
		OBFS:     query.Get("obfs"),
		OBFSPass: query.Get("obfs-password"),
		Remark:   remark,
	}

	// [၂] Outbound တွေက လှမ်းသုံးမယ့် StreamField ကို Initialize လုပ်ပေးပါ
	p.StreamField = &StreamField{
		Network:          "udp",
		StreamSecurity:   "tls",
		ServerName:       p.Config.SNI,
		TLSAllowInsecure: query.Get("insecure"),
	}

	jsonData, err := json.MarshalIndent(p.Config, "", "  ")
	if err != nil {
		return ""
	}
	return string(jsonData)
}

// [၃] Outbound logic က ခေါ်သုံးမယ့် Method များ (ဒါတွေမပါရင် Build ကျပါလိမ့်မယ်)
func (p *ParserHysteria2) GetAddr() string {
	return p.Config.Server
}

func (p *ParserHysteria2) GetPort() int {
	return p.Config.Port
}

func (p *ParserHysteria2) ShowJSON(rawUri string) {
	result := p.Parse(rawUri)
	fmt.Println(result)
}


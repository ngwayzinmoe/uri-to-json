package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Hysteria2Config struct for JSON output
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
	Config Hysteria2Config
}

func (p *ParserHysteria2) Parse(rawUri string) string {
	u, err := url.Parse(rawUri)
	if err != nil {
		return ""
	}

	// Remark (Tag) ကို ရယူခြင်း
	remark := u.Fragment
	if remark != "" {
		if decodedRemark, err := url.QueryUnescape(remark); err == nil {
			remark = decodedRemark
		}
	}

	// Port ကို ပြောင်းလဲခြင်း
	port, _ := strconv.Atoi(u.Port())

	// Query parameters များ ရယူခြင်း
	query := u.Query()
	
	// Insecure check (insecure or allow_insecure)
	insecure := query.Get("insecure") == "1" || query.Get("allow_insecure") == "1"

	p.Config = Hysteria2Config{
		Server:   u.Hostname(),
		Port:     port,
		Auth:     u.User.Username(), // Hysteria2 မှာ password က user part မှာရှိတယ်
		SNI:      query.Get("sni"),
		Insecure: insecure,
		OBFS:     query.Get("obfs"),
		OBFSPass: query.Get("obfs-password"),
		Remark:   remark,
	}

	// JSON အဖြစ် ပြောင်းလဲခြင်း
	jsonData, err := json.MarshalIndent(p.Config, "", "  ")
	if err != nil {
		return ""
	}

	return string(jsonData)
}

func (p *ParserHysteria2) ShowJSON(rawUri string) {
	result := p.Parse(rawUri)
	fmt.Println(result)
}


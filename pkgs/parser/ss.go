package parser

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var SSMethod map[string]struct{} = map[string]struct{}{
	"2022-blake3-aes-128-gcm":       {},
	"2022-blake3-aes-256-gcm":       {},
	"2022-blake3-chacha20-poly1305": {},
	"none":                          {},
	"aes-128-gcm":                   {},
	"aes-192-gcm":                   {},
	"aes-256-gcm":                   {},
	"chacha20-ietf-poly1305":        {},
	"xchacha20-ietf-poly1305":       {},
	"aes-128-ctr":                   {},
	"aes-192-ctr":                   {},
	"aes-256-ctr":                   {},
	"aes-128-cfb":                   {},
	"aes-192-cfb":                   {},
	"aes-256-cfb":                   {},
	"rc4-md5":                       {},
	"chacha20-ietf":                 {},
	"xchacha20":                     {},
}

type ParserSS struct {
	Address  string
	Port     int
	Method   string
	Password string

	Host     string
	Mode     string
	Mux      string
	Path     string
	Plugin   string
	OBFS     string
	OBFSHost string

	*StreamField
}

func (that *ParserSS) Parse(rawUri string) {
	// Fragments (#...) ကို ခဏဖယ်ထားမယ် (Remark တွေအတွက်)
	if idx := strings.Index(rawUri, "#"); idx != -1 {
		rawUri = rawUri[:idx]
	}

	rawUri = that.handleSS(rawUri)
	u, err := url.Parse(rawUri)
	if err != nil {
		return
	}

	that.StreamField = &StreamField{}
	that.Address = u.Hostname()
	that.Port, _ = strconv.Atoi(u.Port())

	userInfo := u.User.String()
	// အကယ်၍ UserInfo ထဲမှာ ':' မပါရင် ဒါဟာ Base64 ဖြစ်ဖို့များတယ်
	if !strings.Contains(userInfo, ":") {
		decoded, err := base64.StdEncoding.DecodeString(userInfo)
		if err == nil {
			userInfo = string(decoded)
		} else {
			// တချို့ Base64 တွေက Padding (=) မပါတတ်လို့ RawStdEncoding နဲ့ပါ စမ်းမယ်
			decoded, err = base64.RawStdEncoding.DecodeString(userInfo)
			if err == nil {
				userInfo = string(decoded)
			}
		}
	}

	// Method နဲ့ Password ခွဲမယ်
	parts := strings.SplitN(userInfo, ":", 2)
	if len(parts) == 2 {
		that.Method = parts[0]
		that.Password = parts[1]
	} else {
		that.Method = parts[0]
	}

	// Alias တွေ ပြင်မယ်
	if that.Method == "rc4" {
		that.Method = "rc4-md5"
	}
	if _, ok := SSMethod[that.Method]; !ok {
		that.Method = "none"
	}

	query := u.Query()
	that.Host = query.Get("host")
	that.Mode = query.Get("mode")
	that.Mux = query.Get("mux")
	that.Path = query.Get("path")
	that.Plugin = query.Get("plugin")
	that.OBFS = query.Get("obfs")
	that.OBFSHost = query.Get("obfs-host")
}

func (that *ParserSS) handleSS(rawUri string) string {
	return strings.ReplaceAll(rawUri, "#ss#\u00261@", "@")
}

func (that *ParserSS) GetAddr() string {
	return that.Address
}

func (that *ParserSS) GetPort() int {
	return that.Port
}

func (that *ParserSS) Show() {
	fmt.Printf("addr: %s, port: %d, method: %s, password: %s\n",
		that.Address,
		that.Port,
		that.Method,
		that.Password)
}

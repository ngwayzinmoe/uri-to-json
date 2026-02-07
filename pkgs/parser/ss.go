package parser

import (
	"encoding/base64"
	"fmt" // fmt ကို ထည့်သွင်းလိုက်ပါပြီ
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
	// [၁] userInfo ကို အရင် Unescape လုပ်မယ် ( + တွေ space မဖြစ်သွားအောင်)
	if decodedInfo, err := url.QueryUnescape(userInfo); err == nil {
		userInfo = decodedInfo
	}

	// [၂] Base64 Decode logic (UserInfo ထဲမှာ ":" မပါရင်)
	if !strings.Contains(userInfo, ":") {
		decoded, err := base64.StdEncoding.DecodeString(userInfo)
		if err != nil {
			// URL safe base64 ကိုပါ စမ်းဖတ်မယ်
			decoded, _ = base64.URLEncoding.DecodeString(userInfo)
			if decoded == nil {
				decoded, _ = base64.RawStdEncoding.DecodeString(userInfo)
			}
		}
		if decoded != nil {
			userInfo = string(decoded)
		}
	}

	parts := strings.SplitN(userInfo, ":", 2)
	if len(parts) == 2 {
		that.Method = parts[0]
		// Password ကိုလည်း တစ်ခါထပ် Unescape လုပ်ပေးခြင်းက ပိုစိတ်ချရပါတယ်
		pass, _ := url.QueryUnescape(parts[1])
		that.Password = pass
	} else {
		that.Method = parts[0]
	}
	if that.Method == "rc4" { that.Method = "rc4-md5" }
	if _, ok := SSMethod[that.Method]; !ok { that.Method = "none" }

	query := u.Query()
	that.Host = query.Get("host")
	that.Mode = query.Get("mode")
	that.Mux = query.Get("mux")
	that.Path = query.Get("path")
	that.Plugin = query.Get("plugin")
	that.OBFS = query.Get("obfs")
	that.OBFSHost = query.Get("obfs-host")

	// UoT Logic
	if query.Get("uot") == "1" || that.Mode == "websocket" {
		that.StreamField.UoT = true
	}
}

func (that *ParserSS) handleSS(rawUri string) string {
	return strings.ReplaceAll(rawUri, "#ss#\u00261@", "@")
}

func (that *ParserSS) GetAddr() string { return that.Address }
func (that *ParserSS) GetPort() int    { return that.Port }

// Show() function အတွက် fmt က အခု အလုပ်လုပ်ပါပြီ
func (that *ParserSS) Show() {
	fmt.Printf("addr: %s, port: %d, method: %s, password: %s\n",
		that.Address,
		that.Port,
		that.Method,
		that.Password)
}


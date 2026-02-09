package parser

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type StreamField struct{}

var SSMethod map[string]struct{} = map[string]struct{}{
	"chacha20-ietf-poly1305":        {},
	"aes-256-gcm":                   {},
	"aes-128-gcm":                   {},
	// ... (ကျန်တဲ့ method တွေ ဒီမှာ ထည့်ထားပါ)
}

type ParserSS struct {
	Address  string
	Port     int
	Method   string
	Password string
	*StreamField
}

func (that *ParserSS) Parse(rawUri string) {
	that.StreamField = &StreamField{}
	
	// 1. Fragment (#) ကို အရင်ဖယ်ထုတ်မယ်
	mainPart := rawUri
	if idx := strings.Index(rawUri, "#"); idx != -1 {
		mainPart = rawUri[:idx]
	}

	// 2. ss:// prefix ကို ဖယ်မယ်
	if strings.HasPrefix(mainPart, "ss://") {
		mainPart = mainPart[5:]
	}

	// 3. @ ကို ရှာပြီး userinfo နဲ့ host:port ကို ခွဲမယ်
	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		// @ မပါရင် တစ်ခုလုံးက base64 ဖြစ်နိုင်တယ်
		that.handleBase64Format(mainPart)
		return
	}

	// User Info အပိုင်း (method:password)
	userInfoEnc := mainPart[:atIdx]
	// Host နှင့် Port အပိုင်း
	addrPort := mainPart[atIdx+1:]

	// 4. Address နဲ့ Port ကို ခွဲထုတ်မယ်
	if strings.Contains(addrPort, ":") {
		parts := strings.Split(addrPort, ":")
		that.Address = parts[0]
		that.Port, _ = strconv.Atoi(parts[1])
	} else {
		that.Address = addrPort
	}

	// 5. UserInfo ကို Decode လုပ်မယ် (Plain text ရော Base64 ပါ handle လုပ်မယ်)
	userInfoDec := userInfoEnc
	// URL-encoded ဖြစ်နေနိုင်တာကို unescape အရင်လုပ် (%2B -> +)
	if s, err := url.QueryUnescape(userInfoEnc); err == nil {
		userInfoDec = s
	}

	// method:password ပုံစံရှိမရှိ စစ်မယ်
	if strings.Contains(userInfoDec, ":") {
		that.extractMethodPass(userInfoDec)
	} else {
		// method:password မဟုတ်ရင် base64 ဖြစ်နိုင်လို့ decode လုပ်ကြည့်မယ်
		if decoded, err := base64.StdEncoding.DecodeString(userInfoDec); err == nil {
			that.extractMethodPass(string(decoded))
		}
	}
}

// Method နဲ့ Password ခွဲထုတ်တဲ့ Helper
func (that *ParserSS) extractMethodPass(info string) {
	parts := strings.SplitN(info, ":", 2)
	if len(parts) == 2 {
		that.Method = parts[0]
		that.Password = parts[1]
	} else {
		that.Method = parts[0]
	}
}

// တစ်ခုလုံး base64 ဖြစ်နေတဲ့ format အတွက် (ss://YWVzLTEyODtnY206dGVzdEAxMjcuMC4wLjE6MTIzNA==)
func (that *ParserSS) handleBase64Format(data string) {
	// Padding ညှိမယ်
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err == nil {
		// Decode ရလာတဲ့ string ကို @ ပါတဲ့ link အနေနဲ့ ပြန် parse မယ်
		that.Parse("ss://" + string(decoded))
	}
}

func (that *ParserSS) Show() {
	fmt.Printf("addr: %s, port: %d, method: %s, password: %s\n", 
		that.Address, that.Port, that.Method, that.Password)
}

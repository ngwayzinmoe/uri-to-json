package parser

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var SSMethod = map[string]struct{}{
	"aes-128-gcm":            {},
	"aes-256-gcm":            {},
	"chacha20-ietf-poly1305": {},
	"xchacha20-ietf-poly1305": {},
	"none":                   {},
}

type ParserSS struct {
	Address  string
	Port     int
	Method   string
	Password string
	Remark   string
	Plugin string
	OBFS string
	OBFSHost string
	Mode string
	
	// အရင်ကပါတဲ့ StreamField ကိုလည်း ပြန်ထည့်ထားပေးပါတယ် (XUDP/UoT အတွက်)
	*StreamField
}

func (p *ParserSS) Parse(raw string) error {
	if !strings.HasPrefix(raw, "ss://") {
		return errors.New("not ss://")
	}

	p.StreamField = &StreamField{} // Initialize StreamField

	// Remark Parsing
	if i := strings.Index(raw, "#"); i != -1 {
		p.Remark, _ = url.QueryUnescape(raw[i+1:])
		raw = raw[:i]
	}

	raw = strings.TrimPrefix(raw, "ss://")

	// SIP002 format (method:pass@host:port)
	if strings.Contains(raw, "@") {
		return p.parseSIP002(raw)
	}

	// Classic format (BASE64 ONLY)
	return p.parseClassic(raw)
}

func (p *ParserSS) parseSIP002(raw string) error {
	parts := strings.SplitN(raw, "@", 2)
	if len(parts) != 2 {
		return errors.New("invalid sip002")
	}

	// [၁] UserInfo (Method:Pass) ကို Unescape လုပ်ပြီးမှ Decode လုပ်မယ်
	userInfoRaw := parts[0]
	if decodedInfo, err := url.QueryUnescape(userInfoRaw); err == nil {
		userInfoRaw = decodedInfo
	}

	userBytes, err := decodeSSBase64(userInfoRaw)
	if err != nil {
		return err
	}

	user := string(userBytes)
	mp := strings.SplitN(user, ":", 2)
	if len(mp) != 2 {
		return errors.New("invalid method:password")
	}

	p.Method = normalizeMethod(mp[0])
	
	// [၂] Password ထဲက Special Character တွေကို Unescape လုပ်ပေးမယ်
	pass, _ := url.QueryUnescape(mp[1])
	p.Password = pass

	// Host:Port & Query params
	hostPart := parts[1]
	// URL parse သုံးပြီး Query ပါရင် handle လုပ်မယ်
	u, err := url.Parse("http://" + hostPart)
	if err != nil {
		return err
	}

	p.Address = u.Hostname()
	p.Port, _ = strconv.Atoi(u.Port())

	//Query Plugin data into model
	query := u.Query()
	p.Plugin = query.Get("plugin")
	p.OBFS = query.Get("obfs")
	p.OBFSHost = query.Get("obfs-host")
	p.Mode = query.Get("mode")

	// UoT Logic (Query ထဲမှာ uot=1 ပါရင် ဖွင့်ပေးမယ်)
	if query.Get("uot") == "1" {
		p.StreamField.UoT = true
	}

	return p.validate()
}

func (p *ParserSS) parseClassic(raw string) error {
	decoded, err := decodeSSBase64(raw)
	if err != nil {
		return err
	}

	s := string(decoded)
	mpHost := strings.SplitN(s, "@", 2)
	if len(mpHost) != 2 {
		return errors.New("invalid classic ss")
	}

	mp := strings.SplitN(mpHost[0], ":", 2)
	if len(mp) != 2 {
		return errors.New("invalid method:password")
	}

	p.Method = normalizeMethod(mp[0])
	
	// Password Unescape
	pass, _ := url.QueryUnescape(mp[1])
	p.Password = pass

	host, portStr, ok := strings.Cut(mpHost[1], ":")
	if !ok {
		return errors.New("invalid host:port")
	}

	p.Address = host
	p.Port, _ = strconv.Atoi(portStr)

	return p.validate()
}

func (p *ParserSS) validate() error {
	if p.Address == "" || p.Port <= 0 {
		return errors.New("invalid address or port")
	}
	return nil
}

func normalizeMethod(m string) string {
	m = strings.ToLower(m)
	if m == "rc4" { return "rc4-md5" }
	return m
}

func decodeSSBase64(s string) ([]byte, error) {
	// Base64 padding and URL safety
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	switch len(s) % 4 {
	case 2: s += "=="
	case 3: s += "="
	}

	// [၃] base64 decode logic ပိုခိုင်မာအောင် လုပ်ခြင်း
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	return b, err
}

func (p *ParserSS) Show() {
	if p == nil { return }
	fmt.Printf("SS => addr: %s, port: %d, method: %s, pass: %s, uot: %v\n", 
		p.Address, p.Port, p.Method, p.Password, p.StreamField.UoT)
}


package parser

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

/*
   Supported methods (Xray-safe focused)
*/
var SSMethod = map[string]struct{}{
	"aes-128-gcm":            {},
	"aes-256-gcm":            {},
	"chacha20-ietf-poly1305": {},
	"xchacha20-ietf-poly1305": {},
}

/*
   Result model
*/
type ParserSS struct {
	Address  string
	Port     int
	Method   string
	Password string
	Remark   string
}

/*
   Entry
*/
func (p *ParserSS) Parse(raw string) error {
	if !strings.HasPrefix(raw, "ss://") {
		return errors.New("not ss://")
	}

	// -------- fragment / remark --------
	if i := strings.Index(raw, "#"); i != -1 {
		p.Remark, _ = url.QueryUnescape(raw[i+1:])
		raw = raw[:i]
	}

	raw = strings.TrimPrefix(raw, "ss://")

	// -------- SIP002 format --------
	// ss://BASE64(method:password)@host:port
	if strings.Contains(raw, "@") {
		return p.parseSIP002(raw)
	}

	// -------- Classic format --------
	// ss://BASE64(method:password@host:port)
	return p.parseClassic(raw)
}

/*
   SIP002
*/
func (p *ParserSS) parseSIP002(raw string) error {
	parts := strings.SplitN(raw, "@", 2)
	if len(parts) != 2 {
		return errors.New("invalid sip002")
	}

	// decode userinfo
	userBytes, err := decodeSSBase64(parts[0])
	if err != nil {
		return err
	}

	user := string(userBytes)
	mp := strings.SplitN(user, ":", 2)
	if len(mp) != 2 {
		return errors.New("invalid method:password")
	}

	p.Method = normalizeMethod(mp[0])
	p.Password = mp[1]

	host, portStr, ok := strings.Cut(parts[1], ":")
	if !ok {
		return errors.New("invalid host:port")
	}

	p.Address = host
	p.Port, _ = strconv.Atoi(portStr)

	return p.validate()
}

/*
   Classic
*/
func (p *ParserSS) parseClassic(raw string) error {
	decoded, err := decodeSSBase64(raw)
	if err != nil {
		return err
	}

	// method:password@host:port
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
	p.Password = mp[1]

	host, portStr, ok := strings.Cut(mpHost[1], ":")
	if !ok {
		return errors.New("invalid host:port")
	}

	p.Address = host
	p.Port, _ = strconv.Atoi(portStr)

	return p.validate()
}

/*
   Validation
*/
func (p *ParserSS) validate() error {
	if p.Address == "" || p.Port <= 0 {
		return errors.New("invalid address or port")
	}
	if _, ok := SSMethod[p.Method]; !ok {
		return errors.New("unsupported method")
	}
	return nil
}

/*
   Method normalize
*/
func normalizeMethod(m string) string {
	m = strings.ToLower(m)
	if m == "rc4" {
		m = "rc4-md5"
	}
	return m
}

/*
   Robust Base64 decode
*/
func decodeSSBase64(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.StdEncoding.DecodeString(s)
}

func (p *ParserSS) Show() {
	if p == nil {
		fmt.Println("SS: <nil>")
		return
	}

	fmt.Printf(
		"SS => addr: %s, port: %d, method: %s, password: %s",
		p.Address,
		p.Port,
		p.Method,
		p.Password,
	)

	if p.Remark != "" {
		fmt.Printf(", remark: %s", p.Remark)
	}

	fmt.Println()
}

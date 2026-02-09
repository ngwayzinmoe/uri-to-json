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

// Parse a ss:// URI into ParserSS
func (that *ParserSS) Parse(rawUri string) {
	rawUri = that.handleSS(rawUri)
	rawUri = that.decodeBase64IfNeeded(rawUri)

	u, err := url.Parse(rawUri)
	if err != nil {
		return
	}

	that.StreamField = &StreamField{}
	that.Address = u.Hostname()
	that.Port, _ = strconv.Atoi(u.Port())

	if u.User != nil {
		that.Method = u.User.Username()
		if that.Method == "rc4" {
			that.Method = "rc4-md5"
		}
		if _, ok := SSMethod[that.Method]; !ok {
			that.Method = "none"
		}
		that.Password, _ = u.User.Password() // ⚠️ DO NOT decode again
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

// decode ss://BASE64(...) ONLY if needed
func (that *ParserSS) decodeBase64IfNeeded(rawUri string) string {
	const prefix = "ss://"
	if !strings.HasPrefix(rawUri, prefix) {
		return rawUri
	}

	data := rawUri[len(prefix):]

	// already decoded form
	if strings.Contains(data, "@") {
		return rawUri
	}

	// fragment
	frag := ""
	if i := strings.Index(data, "#"); i >= 0 {
		frag = data[i:]
		data = data[:i]
	}

	// query
	query := ""
	if i := strings.Index(data, "?"); i >= 0 {
		query = data[i:]
		data = data[:i]
	}

	// ✅ handle URL-encoded base64 (%3D, %2F, %2B)
	if s, err := url.PathUnescape(data); err == nil {
		data = s
	}

	// ✅ auto padding
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return rawUri
	}

	return prefix + string(decoded) + query + frag
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
	fmt.Printf(
		"addr: %s, port: %d, method: %s, password: %s\n",
		that.Address,
		that.Port,
		that.Method,
		that.Password,
	)
}


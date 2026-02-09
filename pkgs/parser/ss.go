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

// Added to prevent error

func (that *ParserSS) Parse(rawUri string) {
	rawUri = that.handleSS(rawUri)
	
	u, err := url.Parse(rawUri)
	if err != nil {
		return
	}

	that.StreamField = &StreamField{}
	that.Address = u.Hostname()
	that.Port, _ = strconv.Atoi(u.Port())

	// ✅ SIP002 format handles (ss://base64(method:password)@addr:port)
	if u.User != nil {
		userInfo := u.User.String()
		
		// Decode base64 if user info is still encoded
		if decoded, err := base64.URLEncoding.DecodeString(userInfo); err == nil {
			userInfo = string(decoded)
		} else if decoded, err := base64.StdEncoding.DecodeString(userInfo); err == nil {
			userInfo = string(decoded)
		}

		parts := strings.SplitN(userInfo, ":", 2)
		if len(parts) == 2 {
			that.Method = parts[0]
			that.Password = parts[1]
		} else {
			that.Method = parts[0]
		}

		if that.Method == "rc4" {
			that.Method = "rc4-md5"
		}
		if _, ok := SSMethod[that.Method]; !ok {
			that.Method = "none"
		}
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
	// Handle non-standard prefix and URL encoding
	rawUri = strings.ReplaceAll(rawUri, "#ss#\u00261@", "@")
	
	// Pre-check for Base64 in standard SIP002 URIs
	if strings.Contains(rawUri, "ss://") && !strings.Contains(rawUri, "@") {
		return that.decodeBase64IfNeeded(rawUri)
	}
	return rawUri
}

func (that *ParserSS) decodeBase64IfNeeded(rawUri string) string {
	const prefix = "ss://"
	if !strings.HasPrefix(rawUri, prefix) {
		return rawUri
	}

	data := rawUri[len(prefix):]
	frag := ""
	if i := strings.Index(data, "#"); i >= 0 {
		frag = data[i:]
		data = data[:i]
	}

	// Unescape URL encoded characters like %3D to =
	if s, err := url.QueryUnescape(data); err == nil {
		data = s
	}

	// Add padding if needed
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return rawUri
	}

	return prefix + string(decoded) + frag
}

func (that *ParserSS) GetAddr() string { return that.Address }
func (that *ParserSS) GetPort() int    { return that.Port }

func (that *ParserSS) Show() {
	fmt.Printf(
		"addr: %s, port: %d, method: %s, password: %s\n",
		that.Address,
		that.Port,
		that.Method,
		that.Password,
	)
}

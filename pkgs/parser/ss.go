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

/*
shadowsocks: ['plugin', 'obfs', 'obfs-host', 'mode', 'path', 'mux', 'host']
*/



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

// Parse a ss:// URI (Base64 encoded) into ParserSS struct
func (that *ParserSS) Parse(rawUri string) {
	rawUri = that.handleSS(rawUri)
	rawUri = that.decodeBase64IfNeeded(rawUri)

	if u, err := url.Parse(rawUri); err == nil {
		that.StreamField = &StreamField{}
		that.Address = u.Hostname()
		that.Port, _ = strconv.Atoi(u.Port())
		that.Method = u.User.Username()
		if that.Method == "rc4" {
			that.Method = "rc4-md5"
		}
		if _, ok := SSMethod[that.Method]; !ok {
			that.Method = "none"
		}
		that.Password, _ = u.User.Password()

		query := u.Query()
		that.Host = query.Get("host")
		that.Mode = query.Get("mode")
		that.Mux = query.Get("mux")
		that.Path = query.Get("path")
		that.Plugin = query.Get("plugin")
		that.OBFS = query.Get("obfs")
		that.OBFSHost = query.Get("obfs-host")
	}
}

// decodeBase64IfNeeded checks if ss:// has base64 part and decodes it
func (that *ParserSS) decodeBase64IfNeeded(rawUri string) string {
	const prefix = "ss://"
	if strings.HasPrefix(rawUri, prefix) {
		data := rawUri[len(prefix):]
		// strip #fragment if exists
		fragIdx := strings.Index(data, "#")
		fragment := ""
		if fragIdx != -1 {
			fragment = data[fragIdx:]
			data = data[:fragIdx]
		}
		// strip query if exists
		queryIdx := strings.Index(data, "?")
		query := ""
		if queryIdx != -1 {
			query = data[queryIdx:]
			data = data[:queryIdx]
		}
		// decode base64
		if decoded, err := base64.StdEncoding.DecodeString(data); err == nil {
			return prefix + string(decoded) + query + fragment
		} else if decodedURL, err := base64.RawURLEncoding.DecodeString(data); err == nil {
			return prefix + string(decodedURL) + query + fragment
		}
	}
	return rawUri
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

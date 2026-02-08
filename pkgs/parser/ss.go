package parser

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var SSMethod = map[string]struct{}{
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
shadowsocks query params:
plugin=obfs-local;obfs=http;obfs-host=example.com
plugin=v2ray-plugin;tls;host=example.com;path=/ws
*/

type ParserSS struct {
	Address  string
	Port     int
	Method   string
	Password string

	// plugin & opts
	Plugin     string
	PluginOpts map[string]string

	// legacy fields (compatible)
	Host     string
	Mode     string
	Mux      string
	Path     string
	OBFS     string
	OBFSHost string

	*StreamField
}

func (that *ParserSS) Parse(rawUri string) {
	rawUri = that.handleSS(rawUri)

	u, err := url.Parse(rawUri)
	if err != nil {
		return
	}

	that.StreamField = &StreamField{}
	that.Address = u.Hostname()
	that.Port, _ = strconv.Atoi(u.Port())

	// ---------- user info (method:password) ----------
	user := u.User.Username()

	// try BASE64 format first
	if m, p, err := decodeSSUser(user); err == nil {
		that.Method = m
		that.Password = p
	} else {
		// fallback old format ss://method:pass@
		that.Method = user
		that.Password, _ = u.User.Password()
	}

	if that.Method == "rc4" {
		that.Method = "rc4-md5"
	}
	if _, ok := SSMethod[that.Method]; !ok {
		that.Method = "none"
	}

	// ---------- query ----------
	query := u.Query()

	// plugin support
	that.Plugin, that.PluginOpts = parsePlugin(query.Get("plugin"))

	// legacy fields mapping
	that.Host = query.Get("host")
	that.Mode = query.Get("mode")
	that.Mux = query.Get("mux")
	that.Path = query.Get("path")
	that.OBFS = query.Get("obfs")
	that.OBFSHost = query.Get("obfs-host")
}

func decodeSSUser(user string) (method, password string, err error) {
	// padding fix
	if m := len(user) % 4; m != 0 {
		user += strings.Repeat("=", 4-m)
	}

	data, err := base64.StdEncoding.DecodeString(user)
	if err != nil {
		return "", "", err
	}

	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid ss base64 user")
	}
	return parts[0], parts[1], nil
}

func parsePlugin(raw string) (name string, opts map[string]string) {
	opts = map[string]string{}
	if raw == "" {
		return "", opts
	}

	parts := strings.Split(raw, ";")
	name = parts[0]

	for _, p := range parts[1:] {
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			opts[kv[0]] = kv[1]
		} else {
			opts[p] = "true" // e.g. tls
		}
	}
	return
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
		"addr=%s port=%d method=%s password=%s plugin=%s opts=%v\n",
		that.Address,
		that.Port,
		that.Method,
		that.Password,
		that.Plugin,
		that.PluginOpts,
	)
}

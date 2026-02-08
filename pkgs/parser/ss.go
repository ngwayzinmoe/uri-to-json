package parser

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
)

type ParserSS struct {
	Address  string
	Port     int
	Method   string
	Password string

	Plugin     string
	PluginOpts map[string]string

	*StreamField
}

func (p *ParserSS) Parse(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}

	p.StreamField = &StreamField{}
	p.Address = u.Hostname()
	p.Port, _ = strconv.Atoi(u.Port())

	user := u.User.Username()

	// base64 userinfo
	if b, err := base64.StdEncoding.DecodeString(padBase64(user)); err == nil {
		parts := strings.SplitN(string(b), ":", 2)
		if len(parts) == 2 {
			p.Method = parts[0]
			p.Password = parts[1]
		}
	} else {
		p.Method = user
		p.Password, _ = u.User.Password()
	}

	// plugin
	p.Plugin, p.PluginOpts = parsePlugin(u.Query().Get("plugin"))

	p.BuildStream()
}

func (p *ParserSS) BuildStream() {
	if p.StreamField == nil {
		p.StreamField = &StreamField{}
	}

	switch p.Plugin {

	case "v2ray-plugin":
		p.Network = "ws"

		if p.PluginOpts["tls"] == "true" {
			p.StreamSecurity = "tls"
		}

		p.Host = p.PluginOpts["host"]
		p.ServerName = p.Host
		p.Path = p.PluginOpts["path"]

	case "obfs-local", "simple-obfs":
		p.Network = "tcp"
		p.TCPHeaderType = "http"
		p.Host = p.PluginOpts["obfs-host"]
	}

	// defaults
	if p.Network == "" {
		p.Network = "tcp"
	}

	p.UoT = true
}

func parsePlugin(raw string) (string, map[string]string) {
	opts := map[string]string{}
	if raw == "" {
		return "", opts
	}

	parts := strings.Split(raw, ";")
	name := parts[0]

	for _, p := range parts[1:] {
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			opts[kv[0]] = kv[1]
		} else {
			opts[p] = "true"
		}
	}
	return name, opts
}

func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

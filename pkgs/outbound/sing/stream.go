package sing

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/util/gconv"
)

/*
Xray Stream → Sing-box Transport Mapping

Supports:
- TCP / HTTP
- WebSocket
- gRPC
- QUIC (optional)
- TLS / uTLS / Reality
*/

var SingHTTPandTCP string = `{
	"type": "http",
	"host": [],
	"path": ""
}`

var SingHTTPHeaders string = `{
	"Host": []
}`

var SingWebSocket string = `{
	"type": "ws",
	"path": ""
}`

var SingWebsocketHeaders string = `{
	"Host": ""
}`

var SingGRPC string = `{
	"type": "grpc",
	"service_name": ""
}`

var SingTLS string = `{
	"enabled": true,
	"disable_sni": false,
	"server_name": "",
	"insecure": false
}`

var SinguTLS string = `{
	"enabled": false,
	"fingerprint": ""
}`

var SingReality string = `{
	"enabled": false,
	"public_key": "",
	"short_id": ""
}`

func PrepareStreamStr(cnf *gjson.Json, sf *parser.StreamField) *gjson.Json {
	if sf.Network == "" {
		sf.Network = "tcp" // default
	}

	switch sf.Network {
	case "tcp", "http":
		j := gjson.New(SingHTTPandTCP)
		host := sf.Host
		if host == "" {
			host = sf.ServerName
		}
		if host != "" {
			j.Set("host.0", host)
			h := gjson.New(SingHTTPHeaders)
			h.Set("Host.0", host)
			j = utils.SetJsonObjectByString("headers", h.MustToJsonString(), j)
		}
		if sf.Path != "" {
			SetPathForSingBoxTransport(sf.Path, j)
		}
		cnf = utils.SetJsonObjectByString("transport", j.MustToJsonString(), cnf)

	case "ws":
		j := gjson.New(SingWebSocket)
		host := sf.Host
		if host == "" {
			host = sf.ServerName
		}
		if host != "" {
			j.Set("headers.Host", host)
		}
		if sf.Path == "" {
			sf.Path = "/"
		}
		SetPathForSingBoxTransport(sf.Path, j)
		cnf = utils.SetJsonObjectByString("transport", j.MustToJsonString(), cnf)

	case "grpc":
		j := gjson.New(SingGRPC)
		if sf.GRPCServiceName != "" {
			j.Set("service_name", sf.GRPCServiceName)
		}
		cnf = utils.SetJsonObjectByString("transport", j.MustToJsonString(), cnf)

	case "quic":
		cnf = utils.SetJsonObjectByString("transport", `{"type":"quic"}`, cnf)
	}

	// ===== TLS / uTLS / Reality =====
	if sf.StreamSecurity == "tls" || sf.StreamSecurity == "reality" {
		j := gjson.New(SingTLS)
		if sf.ServerName == "" {
			sf.ServerName = sf.Host
		}
		j.Set("enabled", true)
		j.Set("server_name", sf.ServerName)
		j.Set("insecure", gconv.Bool(sf.TLSAllowInsecure))

		if sf.Fingerprint != "" {
			utls := gjson.New(SinguTLS)
			utls.Set("enabled", true)
			utls.Set("fingerprint", sf.Fingerprint)
			j = utils.SetJsonObjectByString("utls", utls.MustToJsonString(), j)
		}

		if sf.StreamSecurity == "reality" {
			reality := gjson.New(SingReality)
			reality.Set("enabled", true)
			reality.Set("short_id", sf.RealityShortId)
			reality.Set("public_key", sf.RealityPublicKey)
			j = utils.SetJsonObjectByString("reality", reality.MustToJsonString(), j)
		}

		cnf = utils.SetJsonObjectByString("tls", j.MustToJsonString(), cnf)
	}

	return cnf
}

func SetPathForSingBoxTransport(pathStr string, j *gjson.Json) {
	if u := ParseSingBoxPathToURL(pathStr); u != nil {
		if uPath := u.Path; uPath != "" {
			j.Set("path", uPath)
		}
		if ed, err := strconv.Atoi(u.Query().Get("ed")); err == nil && ed > 0 {
			j.Set("max_early_data", ed)
			j.Set("early_data_header_name", "Sec-WebSocket-Protocol")
		}
	}
}

func ParseSingBoxPathToURL(pathStr string) *url.URL {
	if pathStr == "" {
		return nil
	}
	if strings.HasPrefix(pathStr, "/") {
		pathStr = "http://www.test.com" + pathStr
	}
	u, _ := url.Parse(pathStr)
	return u
}

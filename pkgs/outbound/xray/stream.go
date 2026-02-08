package xray

import (
	"strings"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/util/gconv"
)

/*
Xray Outbound StreamSettings Full Complete
Supports:
- TCP / HTTP / WS / gRPC
- TLS / Reality
- Fingerprint, ALPN, Path, Host, MultiMode
- Default values preserved
*/

var XrayStreamBase = `{
	"network": "tcp",
	"security": "none"
}`

var XrayStreamTLSBase = `{
	"serverName": "",
	"allowInsecure": false,
	"alpn": []
}`

var XrayStreamRealityBase = `{
	"shortId": "",
	"fingerprint": "",
	"serverName": "",
	"publicKey": "",
	"spiderX": ""
}`

var XrayStreamTCPNone = `{
	"header": {
		"type": "none"
	}
}`

var XrayStreamTCPHTTP = `{
	"header": {
		"type": "http",
		"request": {
			"path": ["/"],
			"headers": {
				"Host": [""]
			}
		}
	}
}`

var XrayStreamWebSocket = `{
	"path": "/",
	"headers": {
		"Host": ""
	}
}`

var XrayStreamGRPC = `{
	"serviceName": "",
	"multiMode": false,
	"user_agent": "",
	"idle_timeout": 60,
	"health_check_timeout": 20,
	"permit_without_stream": false,
	"initial_windows_size": 0
}`

// ---------------- Prepare Stream ----------------

func PrepareStreamString(sf *parser.StreamField) string {
	stream := gjson.New(XrayStreamBase)

	if sf.Network == "" {
		sf.Network = "tcp"
	}
	stream.Set("network", sf.Network)
	stream.Set("security", sf.StreamSecurity)

	// ---------------- Network Transport ----------------
	switch sf.Network {
	case "tcp":
		if sf.TCPHeaderType == "http" {
			j := gjson.New(XrayStreamTCPHTTP)
			if sf.Path != "" {
				j.Set("header.request.path.0", sf.Path)
			}
			if sf.Host != "" {
				j.Set("header.request.headers.Host.0", sf.Host)
			}
			stream = utils.SetJsonObjectByString("tcpSettings", j.MustToJsonString(), stream)
		} else {
			stream = utils.SetJsonObjectByString("tcpSettings", XrayStreamTCPNone, stream)
		}
	case "ws":
		j := gjson.New(XrayStreamWebSocket)
		if sf.Path == "" {
			sf.Path = "/"
		}
		j.Set("path", sf.Path)
		if sf.Host != "" {
			j.Set("headers.Host", sf.Host)
		}
		stream = utils.SetJsonObjectByString("wsSettings", j.MustToJsonString(), stream)
	case "grpc":
		j := gjson.New(XrayStreamGRPC)
		if sf.GRPCServiceName != "" {
			j.Set("serviceName", sf.GRPCServiceName)
		}
		if sf.GRPCMultiMode == "multi" {
			j.Set("multiMode", true)
		}
		stream = utils.SetJsonObjectByString("grpcSettings", j.MustToJsonString(), stream)
	}

	// ---------------- Security ----------------
	if sf.StreamSecurity == "tls" {
		j := gjson.New(XrayStreamTLSBase)
		sn := sf.ServerName
		if sn == "" {
			sn = sf.Host
		}
		j.Set("serverName", sn)
		j.Set("allowInsecure", gconv.Bool(sf.TLSAllowInsecure))
		if sf.TLSALPN != "" {
			j.Set("alpn", strings.Split(sf.TLSALPN, ","))
		}
		if sf.Fingerprint != "" {
			j.Set("fingerprint", sf.Fingerprint)
		}
		stream = utils.SetJsonObjectByString("tlsSettings", j.MustToJsonString(), stream)
	} else if sf.StreamSecurity == "reality" {
		j := gjson.New(XrayStreamRealityBase)
		sn := sf.ServerName
		if sn == "" {
			sn = sf.Host
		}
		j.Set("serverName", sn)
		j.Set("publicKey", sf.RealityPublicKey)
		j.Set("shortId", sf.RealityShortId)
		j.Set("spiderX", sf.RealitySpiderX)
		j.Set("fingerprint", sf.Fingerprint)
		stream = utils.SetJsonObjectByString("realitySettings", j.MustToJsonString(), stream)
	}

	return stream.MustToJsonString()
}


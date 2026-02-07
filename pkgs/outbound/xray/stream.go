package xray

import (
	"strings"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/util/gconv"
)

var XrayStream string = `{"network": "tcp", "security": "none"}`
var XrayStreamTLS string = `{"serverName": "", "allowInsecure": false}`
var XrayStreamReality string = `{"shortId": "", "fingerprint": "", "serverName": "", "publicKey": "", "spiderX": ""}`
var XrayStreamTCPNone string = `{"header": {"type": "none"}}`
var XrayStreamWebSocket string = `{"path": "/", "headers": {"Host": ""}}`
var XrayStreamGRPC string = `{"serviceName": "", "multiMode": false}`

func PrepareStreamString(sf *parser.StreamField) string {
	if sf == nil { return "{}" }
	stream := gjson.New(XrayStream)
	
	if sf.Network == "" { sf.Network = "tcp" }
	stream.Set("network", sf.Network)
	stream.Set("security", sf.StreamSecurity)

	// [၁] Packet Encoding (VLESS Reality/Trojan အတွက် အရေးကြီး)
	if sf.PacketEncoding != "" {
		stream.Set("packetEncoding", sf.PacketEncoding)
	}

	switch sf.Network {
	case "tcp":
		if sf.TCPHeaderType == "http" {
			j := gjson.New(`{"header":{"type":"http","request":{"path":["/"],"headers":{"Host":[""]}}}}`)
			j.Set("header.request.path.0", sf.Path)
			j.Set("header.request.headers.Host.0", sf.Host)
			stream.Set("tcpSettings", j.Map())
		} else {
			stream.Set("tcpSettings", gjson.New(XrayStreamTCPNone).Map())
		}
	case "ws":
		j := gjson.New(XrayStreamWebSocket)
		j.Set("path", sf.Path)
		j.Set("headers.Host", sf.Host)
		stream.Set("wsSettings", j.Map())
	case "grpc":
		j := gjson.New(XrayStreamGRPC)
		j.Set("serviceName", sf.GRPCServiceName)
		j.Set("multiMode", sf.GRPCMultiMode == "multi")
		stream.Set("grpcSettings", j.Map())
	}

	// Security Settings
	if sf.StreamSecurity == "tls" {
		j := gjson.New(XrayStreamTLS)
		j.Set("serverName", sf.ServerName)
		j.Set("allowInsecure", gconv.Bool(sf.TLSAllowInsecure))
		if sf.TLSALPN != "" {
			j.Set("alpn", strings.Split(sf.TLSALPN, ","))
		}
		if sf.Fingerprint != "" {
			j.Set("fingerprint", sf.Fingerprint)
		}
		stream.Set("tlsSettings", j.Map())
	} else if sf.StreamSecurity == "reality" {
		j := gjson.New(XrayStreamReality)
		j.Set("serverName", sf.ServerName)
		j.Set("publicKey", sf.RealityPublicKey)
		j.Set("shortId", sf.RealityShortId)
		j.Set("spiderX", sf.RealitySpiderX)
		j.Set("fingerprint", sf.Fingerprint)
		stream.Set("realitySettings", j.Map())
	}

	return stream.MustToJsonString()
}

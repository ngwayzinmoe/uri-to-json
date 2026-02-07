package xray

import (
	"strings"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/util/gconv"
)

/*
https://xtls.github.io/config/transport.html#streamsettingsobject

{
  "network": "tcp",
  "security": "none",
  "tlsSettings": {},
  "tcpSettings": {},
  "kcpSettings": {},
  "wsSettings": {},
  "httpSettings": {},
  "quicSettings": {},
  "dsSettings": {},
  "grpcSettings": {},
  "sockopt": {
    "mark": 0,
    "tcpFastOpen": false,
    "tproxy": "off",
    "domainStrategy": "AsIs",
    "dialerProxy": "",
    "acceptProxyProtocol": false,
    "tcpKeepAliveInterval": 0
  }
}

TLSSettings:
{
  "serverName": "xray.com",
  "rejectUnknownSni": false,
  "allowInsecure": false,
  "alpn": ["h2", "http/1.1"],
  "minVersion": "1.2",
  "maxVersion": "1.3",
  "cipherSuites": "此处填写你需要的加密套件名称,每个套件名称之间用:进行分隔",
  "certificates": [],
  "disableSystemRoot": false,
  "enableSessionResumption": false,
  "fingerprint": "",
  "pinnedPeerCertificateChainSha256": [""]
}

TCPSettings:
https://xtls.github.io/config/transports/tcp.html#tcpobject
{
  "acceptProxyProtocol": false,
  "header": {
    "type": "none"
  }
}
HttpHeaderObject:
{
  "type": "http",
  "request": {},
  "response": {}
}

WSSettings:
{
  "acceptProxyProtocol": false,
  "path": "/",
  "headers": {
    "Host": "xray.com"
  }
}

GRPCSettings:
{
  "serviceName": "name",
  "multiMode": false,
  "user_agent": "custom user agent",
  "idle_timeout": 60,
  "health_check_timeout": 20,
  "permit_without_stream": false,
  "initial_windows_size": 0
}

HTTPSettings:
{
  "host": ["xray.com"],
  "path": "/random/path",
  "read_idle_timeout": 10,
  "health_check_timeout": 15,
  "method": "PUT",
  "headers": {
    "Header": ["value"]
  }
}

*/

var XrayStream string = `{
	"network": "tcp",
	"security": "none"
}`

var XrayStreamTLS string = `{
	"serverName": "xray.com",
	"allowInsecure": true
}`

var XrayStreamReality string = `{
  "shortId": "",
  "fingerprint": "",
  "serverName": "",
  "publicKey": "",
  "spiderX": ""
}`

var XrayStreamTCPNone string = `{
	"header": {
	  "type": "none"
	}
}`

var XrayStreamTCPHTTP string = `{
  "header": {
      "type": "http",
      "request": {
          "path": ["/"],
          "headers": {
              "Host": ["fast.com"]
          }
      }
  }
}`

var XrayStreamWebSocket string = `{
	"path": "/",
	"headers": {
	  "Host": "xray.com"
	}
}`

var XrayStreamHTTP string = `{
	"host": [""],
	"path": ""
}`

var XrayStreamGRPC string = `{
	"serviceName": "",
	"multiMode": false
}`

func PrepareStreamString(sf *parser.StreamField) string {
	stream := gjson.New(XrayStream)
	
	// Network မရှိရင် default tcp သုံးမယ်
	if sf.Network == "" {
		sf.Network = "tcp"
	}
	stream.Set("network", sf.Network)
	stream.Set("security", sf.StreamSecurity)

	switch sf.Network {
	case "tcp":
		if sf.TCPHeaderType == "http" {
			j := gjson.New(XrayStreamTCPHTTP)
			j.Set("header.request.path.0", sf.Path)
			j.Set("header.request.headers.Host.0", sf.Host)
			// Xray standard က tcpSettings ဖြစ်ပါတယ်
			stream = utils.SetJsonObjectByString("tcpSettings", j.MustToJsonString(), stream)
		} else {
			stream = utils.SetJsonObjectByString("tcpSettings", XrayStreamTCPNone, stream)
		}
	case "ws":
		j := gjson.New(XrayStreamWebSocket)
		if sf.Path == "" { sf.Path = "/" }
		j.Set("path", sf.Path)
		j.Set("headers.Host", sf.Host)
		stream = utils.SetJsonObjectByString("wsSettings", j.MustToJsonString(), stream)
	case "grpc":
		j := gjson.New(XrayStreamGRPC)
		j.Set("serviceName", sf.GRPCServiceName)
		if sf.GRPCMultiMode == "multi" {
			j.Set("multiMode", true)
		}
		stream = utils.SetJsonObjectByString("grpcSettings", j.MustToJsonString(), stream)
	}

	// Security Settings
	if sf.StreamSecurity == "tls" {
		j := gjson.New(XrayStreamTLS)
		sn := sf.ServerName
		if sn == "" { sn = sf.Host }
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
		j := gjson.New(XrayStreamReality)
		sn := sf.ServerName
		if sn == "" { sn = sf.Host }
		j.Set("serverName", sn)
		j.Set("publicKey", sf.RealityPublicKey)
		j.Set("shortId", sf.RealityShortId)
		j.Set("spiderX", sf.RealitySpiderX)
		j.Set("fingerprint", sf.Fingerprint)
		stream = utils.SetJsonObjectByString("realitySettings", j.MustToJsonString(), stream)
	}

	return stream.MustToJsonString()
}

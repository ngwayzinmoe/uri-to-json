package sing

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/util/gconv"
)

// PrepareStreamStr က Parser ဆီကရတဲ့ StreamField data တွေကို Sing-box JSON format ထဲ ထည့်ပေးတာပါ
func PrepareStreamStr(cnf *gjson.Json, sf *parser.StreamField) (result *gjson.Json) {
	if sf == nil || cnf == nil {
		return cnf
	}

	// [၁] Shadowsocks UDP over TCP (UoT) - Gaming အတွက် အရေးကြီးပါတယ်
	if sf.UoT {
		cnf.Set("udp_over_tcp", true)
	}

	// [၂] Transport (Network) Settings
	var transport map[string]interface{}
	switch sf.Network {
	case "ws":
		ws := map[string]interface{}{
			"type": "ws",
			"path": sf.Path,
		}
		if sf.Host != "" {
			ws["headers"] = map[string]string{"Host": sf.Host}
		}
		// URL path ထဲကနေ max_early_data (ed) ကို ဆွဲထုတ်ဖို့ helper function သုံးမယ်
		tempJ := gjson.New(ws)
		SetPathForSingBoxTransport(sf.Path, tempJ)
		transport = tempJ.Map()

	case "grpc":
		transport = map[string]interface{}{
			"type":         "grpc",
			"service_name": sf.GRPCServiceName,
		}
	}

	if transport != nil {
		cnf.Set("transport", transport)
	}

	// [၃] TLS / Reality Security Settings
	if sf.StreamSecurity == "tls" || sf.StreamSecurity == "reality" {
		tls := map[string]interface{}{
			"enabled":     true,
			"server_name": sf.ServerName,
			"insecure":    gconv.Bool(sf.TLSAllowInsecure),
		}

		// uTLS Fingerprint (chrome, safari စတာတွေအတွက်)
		if sf.Fingerprint != "" {
			tls["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": sf.Fingerprint,
			}
		}

		// Reality settings
		if sf.StreamSecurity == "reality" {
			tls["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": sf.RealityPublicKey,
				"short_id":   sf.RealityShortId,
			}
		}
		cnf.Set("tls", tls)
	}

	result = cnf
	return
}

// --- အောက်က Helper Functions တွေကိုလည်း မဖျက်ဘဲ ထားပေးပါ ---

func SetPathForSingBoxTransport(pathStr string, j *gjson.Json) {
	if u := ParseSingBoxPathToURL(pathStr); u != nil {
		if uPath := u.Path; uPath != "" {
			j.Set("path", uPath)
		}
		// path ထဲမှာ ed=2048 စသဖြင့် ပါလာရင် sing-box transport ထဲ ထည့်ပေးတာပါ
		if ed, err := strconv.Atoi(u.Query().Get("ed")); err == nil && ed > 0 {
			j.Set("max_early_data", ed)
			j.Set("early_data_header_name", "Sec-WebSocket-Protocol")
		}
	}
}

func ParseSingBoxPathToURL(pathStr string) (result *url.URL) {
	if pathStr == "" {
		return
	}
	if strings.HasPrefix(pathStr, "/") {
		pathStr = "http://www.test.com" + pathStr
	}
	result, _ = url.Parse(pathStr)
	return
}

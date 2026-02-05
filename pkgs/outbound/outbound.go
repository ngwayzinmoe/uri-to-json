package outbound

import (
	"fmt"

	"github.com/dev7dev/uri-to-json/pkgs/outbound/sing"
	"github.com/dev7dev/uri-to-json/pkgs/outbound/xray"
	"github.com/dev7dev/uri-to-json/pkgs/parser"
	"github.com/dev7dev/uri-to-json/pkgs/utils"
)

type ClientType string

const (
	XrayCore ClientType = "xray"
	SingBox  ClientType = "sing"
)

func GetOutbound(clientType ClientType, rawUri string) (result IOutbound) {
	scheme := utils.ParseScheme(rawUri)
	switch clientType {
	case XrayCore:
		switch scheme {
		case parser.SchemeVmess:
			result = &xray.VmessOut{RawUri: rawUri}
		case parser.SchemeVless:
			result = &xray.VlessOut{RawUri: rawUri}
		case parser.SchemeTrojan:
			result = &xray.TrojanOut{RawUri: rawUri}
		case parser.SchemeSS:
			result = &xray.ShadowSocksOut{RawUri: rawUri}
		case parser.SchemeHysteria2: // [၁] Xray အတွက် Hysteria2 ကို Register လုပ်ခြင်း
			result = &xray.Hysteria2Out{RawUri: rawUri}
		default:
			fmt.Println("unsupported protocol for Xray: ", scheme)
		}
	case SingBox:
		switch scheme {
		case parser.SchemeVmess:
			result = &sing.SVmessOut{RawUri: rawUri}
		case parser.SchemeVless:
			result = &sing.SVlessOut{RawUri: rawUri}
		case parser.SchemeTrojan:
			result = &sing.STrojanOut{RawUri: rawUri}
		case parser.SchemeSS:
			result = &sing.SShadowSocksOut{RawUri: rawUri}
		case parser.SchemeSSR:
			result = &sing.SShadowSocksROut{RawUri: rawUri}
		case parser.SchemeWireguard:
			result = &sing.SWireguardOut{RawUri: rawUri}
		case parser.SchemeHysteria2: // [၂] Sing-box အတွက် Hysteria2 ကို Register လုပ်ခြင်း
			result = &sing.SHysteria2Out{RawUri: rawUri}
		default:
			fmt.Println("unsupported protocol for Sing-box: ", scheme)
		}
	default:
		fmt.Println("unsupported client type")
	}
	return
}

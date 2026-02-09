package parser

import (
	"net/url"
	"strings"

	"github.com/gvcgo/goutils/pkgs/crypt"
	"github.com/gvcgo/goutils/pkgs/gtui"
)

const (
	SchemeSS        string = "ss://"
	SchemeSSR       string = "ssr://"
	SchemeTrojan    string = "trojan://"
	SchemeVless     string = "vless://"
	SchemeVmess     string = "vmess://"
	SchemeWireguard string = "wireguard://"
	SchemeHysteria2 string = "hysteria2://" // [၁] Hysteria2 ထည့်လိုက်ပါ
)

// SafeBase64Decode handles standard and URL-safe Base64 with proper padding
func SafeBase64Decode(str string) string {
	if str == "" {
		return ""
	}
	// URL Safe replacements
	str = strings.ReplaceAll(str, "-", "+")
	str = strings.ReplaceAll(str, "_", "/")

	// Add missing padding if necessary
	for len(str)%4 != 0 {
		str += "="
	}
	return crypt.DecodeBase64(str)
}

func GetVpnScheme(rawUri string) string {
	sep := "://"
	if !strings.Contains(rawUri, sep) {
		return ""
	}
	sList := strings.Split(rawUri, sep)
	return sList[0] + sep
}

func HandleQuery(rawUri string) (result string) {
	result = rawUri
	if !strings.Contains(rawUri, "?") {
		return
	}
	sList := strings.Split(rawUri, "?")
	query := sList[1]
	// Hysteria2 link တွေမှာ ပါတတ်တဲ့ semicolon query တွေကို handle လုပ်ဖို့
	if strings.Contains(query, ";") && !strings.Contains(query, "&") {
		result = sList[0] + "?" + strings.ReplaceAll(sList[1], ";", "&")
	}
	return
}

func ParseRawUri(rawUri string) (result string) {
	// [၂] VMess အတွက် base64 ကို အရင်ကိုင်တွယ်မယ်
	if strings.HasPrefix(rawUri, SchemeVmess) {
		// VMess processing
		b64Part := strings.Split(rawUri, "://")[1]
		if r := SafeBase64Decode(b64Part); r != "" {
			result = SchemeVmess + r
		} else {
			result = rawUri
		}
		return
	}

	// [၃] Character တွေကို သန့်စင်မယ်
	if strings.Contains(rawUri, "\u0026") {
		rawUri = strings.ReplaceAll(rawUri, "\u0026", "&")
	}
	
	// Remark တွေမှာ space ပါရင် error မတက်အောင် decode အရင်လုပ်မယ်
	tempUri, _ := url.QueryUnescape(rawUri)
	r, err := url.Parse(tempUri)
	result = tempUri
	if err != nil {
		gtui.PrintError(err)
		return
	}

	// [၄] Hysteria2 သို့မဟုတ် Vless ဆိုရင် UUID တွေကို Base64 decode မလုပ်မိအောင် ကျော်ခဲ့မယ်
	scheme := GetVpnScheme(rawUri)
	if scheme == SchemeVless || scheme == SchemeHysteria2 || scheme == SchemeTrojan {
		result = HandleQuery(tempUri)
		return
	}

	// Shadowsocks (SS) အတွက်သာ Base64 decoding logic ကို သုံးမယ်
	result = tempUri
	host := r.Host
	uname := r.User.Username()
	passw, hasPassword := r.User.Password()

	if !strings.Contains(tempUri, "@") {
		// ss://[base64] format မျိုးအတွက်
		if hostDecrypted := SafeBase64Decode(host); hostDecrypted != "" {
			result = strings.ReplaceAll(tempUri, host, hostDecrypted)
		}
	} else if uname != "" && !hasPassword && !strings.Contains(uname, "-") {
		// ss://[base64]@host:port format မျိုးအတွက်
		if unameDecrypted := SafeBase64Decode(uname); unameDecrypted != "" {
			result = strings.ReplaceAll(tempUri, uname, unameDecrypted)
		}
	} else if hasPassword {
		// ss://method:[base64_password]@host:port format မျိုးအတွက်
		// user:pass format (အကယ်၍ password က base64 ဖြစ်နေခဲ့လျှင်)
		if passwDecrypted := SafeBase64Decode(passw); passwDecrypted != "" {
			result = strings.ReplaceAll(tempUri, passw, passwDecrypted)
		}
	}

	if strings.Contains(result, "%") {
		result, _ = url.QueryUnescape(result)
	}
	result = HandleQuery(result)
	return
}




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
		if r := crypt.DecodeBase64(strings.Split(rawUri, "://")[1]); r != "" {
			result = SchemeVmess + r
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
	host := r.Host
	uname := r.User.Username()
	passw, hasPassword := r.User.Password()

	if !strings.Contains(tempUri, "@") {
		// ss://[base64] format မျိုးအတွက်
		if hostDecrypted := crypt.DecodeBase64(host); hostDecrypted != "" {
			result = strings.ReplaceAll(tempUri, host, hostDecrypted)
		}
	} else if uname != "" && !hasPassword && !strings.Contains(uname, "-") {
		// ss://[base64]@host:port format မျိုးအတွက်
		if unameDecrypted := crypt.DecodeBase64(uname); unameDecrypted != "" {
			result = strings.ReplaceAll(tempUri, uname, unameDecrypted)
		}
	} else if hasPassword {
		// ss://method:[base64_password]@host:port format မျိုးအတွက်
		if passwDecrypted := crypt.DecodeBase64(passw); passwDecrypted != "" {
			result = strings.ReplaceAll(tempUri, passw, passwDecrypted)
		}
	}

	if strings.Contains(result, "%") {
		result, _ = url.QueryUnescape(result)
	}
	result = HandleQuery(result)
	return
}



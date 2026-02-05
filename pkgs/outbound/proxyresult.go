package outbound

import (
	"os"
	"sync"

	"encoding/json"

	"github.com/ngwayzinmoe/uri-to-json/pkgs/parser"
	"github.com/ngwayzinmoe/uri-to-json/pkgs/utils"
	"github.com/gvcgo/goutils/pkgs/gutils"
)

type Result struct {
	Vmess          []*ProxyItem `json:"Vmess"`
	Vless          []*ProxyItem `json:"Vless"`
	ShadowSocks    []*ProxyItem `json:"Shadowsocks"`
	ShadowSocksR   []*ProxyItem `json:"ShadowsocksR"`
	Trojan         []*ProxyItem `json:"Trojan"`
	Hysteria2      []*ProxyItem `json:"Hysteria2"` // [၁] Hysteria2 list အသစ်
	UpdateAt       string       `json:"UpdateAt"`
	VmessTotal     int          `json:"VmessTotal"`
	VlessTotal     int          `json:"VlessTotal"`
	TrojanTotal    int          `json:"TrojanTotal"`
	SSTotal        int          `json:"SSTotal"`
	SSRTotal       int          `json:"SSRTotal"`
	Hysteria2Total int          `json:"Hysteria2Total"` // [၂] Total count field
	totalList      []*ProxyItem
	lock           *sync.Mutex
}

func NewResult() *Result {
	return &Result{
		lock: &sync.Mutex{},
	}
}

func (that *Result) Load(fPath string) {
	if ok, _ := gutils.PathIsExist(fPath); ok {
		if content, err := os.ReadFile(fPath); err == nil {
			that.lock.Lock()
			json.Unmarshal(content, that)
			that.lock.Unlock()
		}
	}
}

func (that *Result) Save(fPath string) {
	if content, err := json.Marshal(that); err == nil {
		that.lock.Lock()
		os.WriteFile(fPath, content, os.ModePerm)
		that.lock.Unlock()
	}
}

func (that *Result) AddItem(proxyItem *ProxyItem) {
	that.lock.Lock()
	defer that.lock.Unlock() // Lock handling ကို ပိုသန့်ရှင်းအောင် defer သုံးထားပါတယ်
	
	if proxyItem == nil {
		return
	}

	switch utils.ParseScheme(proxyItem.RawUri) {
	case parser.SchemeVmess:
		that.Vmess = append(that.Vmess, proxyItem)
		that.VmessTotal++
	case parser.SchemeVless:
		that.Vless = append(that.Vless, proxyItem)
		that.VlessTotal++
	case parser.SchemeTrojan:
		that.Trojan = append(that.Trojan, proxyItem)
		that.TrojanTotal++
	case parser.SchemeSS:
		that.ShadowSocks = append(that.ShadowSocks, proxyItem)
		that.SSTotal++
	case parser.SchemeSSR:
		that.ShadowSocksR = append(that.ShadowSocksR, proxyItem)
		that.SSRTotal++
	case parser.SchemeHysteria2: // [၃] Hysteria2 link ကို case ထည့်ခြင်း
		that.Hysteria2 = append(that.Hysteria2, proxyItem)
		that.Hysteria2Total++
	default:
	}
	that.totalList = append(that.totalList, proxyItem)
}

func (that *Result) Len() int {
	return that.VmessTotal + that.VlessTotal + that.TrojanTotal + that.SSTotal + that.SSRTotal + that.Hysteria2Total
}

func (that *Result) GetTotalList() []*ProxyItem {
	if len(that.totalList) != that.Len() {
		// totalList ကို ပြန်တည်ဆောက်တဲ့အခါ Hysteria2 ကိုပါ ပေါင်းထည့်မယ်
		that.totalList = []*ProxyItem{} // Clear old list
		that.totalList = append(that.totalList, that.Vmess...)
		that.totalList = append(that.totalList, that.Vless...)
		that.totalList = append(that.totalList, that.Trojan...)
		that.totalList = append(that.totalList, that.ShadowSocks...)
		that.totalList = append(that.totalList, that.ShadowSocksR...)
		that.totalList = append(that.totalList, that.Hysteria2...)
	}
	return that.totalList
}

func (that *Result) Clear() {
	that.lock.Lock()
	defer that.lock.Unlock()
	
	that.Vmess = []*ProxyItem{}
	that.VmessTotal = 0
	that.Vless = []*ProxyItem{}
	that.VlessTotal = 0
	that.Trojan = []*ProxyItem{}
	that.TrojanTotal = 0
	that.ShadowSocks = []*ProxyItem{}
	that.SSTotal = 0
	that.ShadowSocksR = []*ProxyItem{}
	that.SSRTotal = 0
	that.Hysteria2 = []*ProxyItem{} // [၄] Clear Hysteria2
	that.Hysteria2Total = 0
	that.totalList = []*ProxyItem{}
}

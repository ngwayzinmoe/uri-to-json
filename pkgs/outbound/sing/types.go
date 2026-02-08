package sing

import "github.com/ngwayzinmoe/uri-to-json/pkgs/parser"

// Common sing-box Shadowsocks outbound
type SingSS struct {
	ParserSS  *parser.ParserSS
	ParserSSR *parser.ParserSSR
}

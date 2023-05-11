package sms

import "encoding/xml"

type Policies struct {
	XMLName xml.Name `xml:"policies"`
	Text    string   `xml:",chardata"`
	Policy  []struct {
		Text       string `xml:",chardata"`
		Name       string `xml:"name,attr"`
		ID         string `xml:"id,attr"`
		Version    string `xml:"version,attr"`
		Iteration  string `xml:"iteration,attr"`
		Locked     string `xml:"locked,attr"`
		UseParent  string `xml:"useParent,attr"`
		Capability string `xml:"capability,attr"`
		Base       struct {
			Text      string `xml:",chardata"`
			Comment   string `xml:"comment"`
			Message   string `xml:"message"`
			Severity  string `xml:"severity"`
			Actionset struct {
				Text     string `xml:",chardata"`
				Indirect string `xml:"indirect,attr"`
				Refid    string `xml:"refid,attr"`
			} `xml:"actionset"`
			SslServer           string `xml:"ssl-server"`
			SslClientProxy      string `xml:"ssl-client-proxy"`
			SslClientDecrypt    string `xml:"ssl-client-decrypt"`
			SslClientTruststore string `xml:"ssl-client-truststore"`
			Recommended         struct {
				Text   string `xml:",chardata"`
				Active string `xml:"active,attr"`
				Refid  string `xml:"refid,attr"`
			} `xml:"recommended"`
			CongestionMitigation struct {
				Text    string `xml:",chardata"`
				Enabled string `xml:"enabled,attr"`
			} `xml:"congestionMitigation"`
		} `xml:"base"`
		Signature struct {
			Text       string `xml:",chardata"`
			Refid      string `xml:"refid,attr"`
			Parameters struct {
				Text  string `xml:",chardata"`
				Param []struct {
					Text      string   `xml:",chardata"`
					Name      string   `xml:"name,attr"`
					Type      string   `xml:"type,attr"`
					Any       string   `xml:"any"`
					Uint      []string `xml:"uint"`
					Service   string   `xml:"service"`
					Portrange struct {
						Text  string `xml:",chardata"`
						Start string `xml:"start"`
						End   string `xml:"end"`
					} `xml:"portrange"`
				} `xml:"param"`
			} `xml:"parameters"`
			Precedence string `xml:"precedence"`
		} `xml:"signature"`
		Zone struct {
			Text string `xml:",chardata"`
			Name string `xml:"name,attr"`
		} `xml:"zone"`
	} `xml:"policy"`
}

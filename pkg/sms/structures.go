package sms

import "encoding/xml"

// Request

type GetFilters struct {
	XMLName xml.Name `xml:"getFilters"`
	Profile Profile  `xml:"profile"`
	Filter  []Filter `xml:"filter"`
}

type SetFilters struct {
	XMLName xml.Name `xml:"setFilters"`
	Profile Profile  `xml:"profile,omitempty"`
	Filter  []Filter `xml:"filter"`
}

type Profile struct {
	ID   string `xml:"id,attr,omitempty"`
	Name string `xml:"name,attr,omitempty"`
}

type PolicyGroup struct {
	//Text  string `xml:",chardata"`
	Refid string `xml:"refid,attr"`
}

type Trigger struct {
	//Text    string `xml:",chardata"`
	Timeout string `xml:"timeout,attr"`
}

type Capability struct {
	//	Text      string `xml:",chardata"`
	Name      string `xml:"name,attr"`
	Enabled   string `xml:"enabled,omitempty"`
	Actionset string `xml:"actionset,omitempty"`
}

type Actionset struct {
	Refid string `xml:"refid,attr,omitempty"`
	Name  string `xml:"name,attr,omitempty"`
}

// 052 457 1815

type Filter struct {
	Name        string       `xml:"name,omitempty"`
	Number      string       `xml:"number,omitempty"`
	SignatureID string       `xml:"signature-id,omitempty"`
	PolicyID    string       `xml:"policy-id,omitempty"`
	Version     string       `xml:"version,omitempty"`
	Locked      string       `xml:"locked,omitempty"`
	UseParent   string       `xml:"useParent,omitempty"`
	Comment     string       `xml:"comment,omitempty"`
	Description string       `xml:"description,omitempty"`
	Severity    string       `xml:"severity,omitempty"`
	Enabled     string       `xml:"enabled,omitempty"`
	Actionset   *Actionset   `xml:"actionset,omitempty"`
	Control     string       `xml:"control,omitempty"`
	Afc         string       `xml:"afc,omitempty"`
	PolicyGroup *PolicyGroup `xml:"policyGroup,omitempty"`
	Trigger     *Trigger     `xml:"trigger"`
	Capability  []Capability `xml:"capability"`
	Status      *Status      `xml:"status"`
}

type Status struct {
	//XMLName xml.Name `xml:"status"`
	Text string `xml:",chardata"`
}

type Filters struct {
	XMLName xml.Name `xml:"filters"`
	Status  *Status  `xml:"status"`
	//	Text                      string   `xml:",chardata"`
	//	NoNamespaceSchemaLocation string   `xml:"noNamespaceSchemaLocation,attr"`
	//Xsi     string `xml:"xsi,attr"`
	Profile struct {
		Text    string `xml:",chardata"`
		Name    string `xml:"name,attr"`
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	} `xml:"profile"`
	Filter []Filter `xml:"filter,omitempty"`
}

type Resultset struct {
	XMLName xml.Name `xml:"resultset"`
	//	Text    string   `xml:",chardata"`
	Table struct {
		//		Text   string `xml:",chardata"`
		Name   string `xml:"name,attr"`
		Column []struct {
			//			Text string `xml:",chardata"`
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"column"`
		Data struct {
			//			Text string `xml:",chardata"`
			R []struct {
				Text string   `xml:",chardata"`
				C    []string `xml:"c"`
			} `xml:"r"`
		} `xml:"data"`
	} `xml:"table"`
}

// For Distribute Profile

type SegmentGroup struct {
	//Text string `xml:",chardata"`
	ID     string  `xml:"id,attr,omitempty"`
	Name   string  `xml:"name,attr,omitempty"`
	Status *Status `xml:"status"`
}

type VirtualSegment struct {
	//Text string `xml:",chardata"`
	ID string `xml:"id"`
}

type DeviceVirtualSegment struct {
	//Text string `xml:",chardata"`
	ID   string `xml:"id,attr"`
	Name string `xml:"name,attr"`
}

type Device struct {
	//	Text           string          `xml:",chardata"`
	ID             string          `xml:"id"`
	VirtualSegment *VirtualSegment `xml:"virtualSegment"`
}

type Distribution struct {
	XMLName        xml.Name        `xml:"distribution"`
	Profile        Profile         `xml:"profile"`
	Priority       string          `xml:"priority"`
	SegmentGroup   *SegmentGroup   `xml:"segmentGroup,omitempty"`
	VirtualSegment *VirtualSegment `xml:"virtualSegment"`
	Device         *Device         `xml:"device"`
}

type Distributions struct { // For reply
	XMLName xml.Name `xml:"distributions"`
	//Profile        Profile         `xml:"profile"`
	SegmentGroup *SegmentGroup `xml:"segmentGroup,omitempty"`
	//VirtualSegment *VirtualSegment `xml:"virtualSegment"`
	//	Device         *Device         `xml:"device"`
}

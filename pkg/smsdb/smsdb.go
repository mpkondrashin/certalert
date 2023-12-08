package smsdb

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

const (
	databaseName = "ExternalAccess"
)

type SMSDB struct {
	db       *sql.DB
	user     string
	password string
	host     string
	port     int
}

func NewSMBDB(user string, password string, host string) *SMSDB {
	return &SMSDB{
		user:     user,
		password: password,
		host:     host,
		port:     3306,
	}
}

func (s *SMSDB) SetPassword(port int) *SMSDB {
	s.port = port
	return s
}

func (s *SMSDB) Open() error {
	dataSourceName := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", s.user, s.password, s.host, s.port, databaseName)
	// parseTime=true
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return fmt.Errorf("sql.Open: %w", err)
	}
	s.db = db
	return nil
}

func (s *SMSDB) Close() {
	if s.db == nil {
		return
	}
	s.db.Close()
}

func (s *SMSDB) Ping() error {
	return s.db.Ping()
}

func (s *SMSDB) iterateTable(query string, where string, callback func(*sql.Rows) error) error {
	if where != "" {
		query = fmt.Sprintf("%s WHERE %s", query, where)
	}
	rows, err := s.db.Query(query)
	if err != nil {
		return fmt.Errorf("sql.Query: %w", err)
	}
	defer rows.Close()
	if rows.Err() != nil {
		return fmt.Errorf("rows.Err: %w", rows.Err())
	}
	for rows.Next() {
		err = callback(rows)
		if err != nil {
			return fmt.Errorf("callback rows: %w", err)
		}
	}
	return nil
}

/*
type Policy struct {
	ID          sql.NullString
	ProfileID   sql.NullString
	SignatureID sql.NullString
	ActionSetID sql.NullString
	Name        sql.NullString
}

func (s *SMSDB) IteratePolicy(where string, callback func(*Policy) error) error {
	query := fmt.Sprintf("SELECT ID,PROFILE_ID,SIGNATURE_ID,ACTIONSET_ID,NAME FROM POLICY")
	return s.iterateTable(query, where, func(rows *sql.Rows) error {
		var p Policy
		if err := rows.Scan(&p.ID, &p.ProfileID, &p.SignatureID, &p.ActionSetID, &p.Name); err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		err := callback(&p)
		if err != nil {
			return fmt.Errorf("callback: %w", err)
		}
		return nil
	})
}

type Signature struct {
	ID                sql.NullString
	Num               int
	Severity          int
	Name              sql.NullString
	Class             sql.NullString
	ProductCategoryID int
	Protocol          sql.NullString
	TaxonomyID        int
	CVEID             sql.NullString
	BagtraqID         sql.NullString
	Description       sql.NullString
	Message           sql.NullString
}

func (s *SMSDB) IterateSignature(where string, callback func(signature *Signature) error) error {
	query := "SELECT ID,NUM,SEVERITY,NAME,CLASS,PRODUCT_CATEGORY_ID,PROTOCOL,TAXONOMY_ID,CVE_ID,BUGTRAQ_ID,DESCRIPTION,MESSAGE FROM SIGNATURE"
	return s.iterateTable(query, where, func(rows *sql.Rows) error {
		var s Signature
		err := rows.Scan(&s.ID, &s.Num, &s.Severity, &s.Name, &s.Class, &s.ProductCategoryID, &s.Protocol, &s.TaxonomyID, &s.CVEID, &s.BagtraqID, &s.Description, &s.Message)
		if err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		if err := callback(&s); err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		return nil
	})
}

type Alert struct {
	SequenceNum         int64
	DeviceShortId       int
	AlertTypeId         uint16
	PolicyId            sql.NullString
	SignatureId         sql.NullString
	BeginTime           int64
	EndTime             int64
	HitCount            int
	SrcIpAddr           int64
	SrcIpAddrHigh       int64
	SrcPort             uint16
	DstIpAddr           int64
	DstIpAddrHigh       int64
	DstPort             uint16
	VirtualSegmentIndex int
	PhysicalPortIn      uint16
	VlanTag             uint16
	Severity            uint8
	PacketTrace         uint8
	DeviceTraceBucket   int
	DeviceTraceBeginSeq int
	DeviceTraceEndSeq   int
	MessageParms        sql.NullString
	Idx                 uint64
	QuarantineAction    sql.NullString
	FlowControl         sql.NullString
	ActionSetUuid       sql.NullString
	ActionSetName       sql.NullString
	RateLimitRate       sql.NullString
	ClientIpAddr        [16]byte
	XffIpAddr           [16]byte
	TcipIpAddr          [16]byte
	UriMethod           sql.NullString
	UriHost             sql.NullString
	UriString           sql.NullString
	SrcUserName         sql.NullString
	SrcDomain           sql.NullString
	SrcMachine          sql.NullString
	DstUserName         sql.NullString
	DstDomain           sql.NullString
	DstMachine          sql.NullString
}
*/
/*
func (s *SMSDB) IterateAlerts(where string, callback func(alert *Alert) error) error {
	query := "SELECT SEQUENCE_NUM,DEVICE_SHORT_ID,ALERT_TYPE_ID,POLICY_ID,SIGNATURE_ID,BEGIN_TIME,END_TIME,HIT_COUNT,SRC_IP_ADDR,SRC_IP_ADDR_HIGH,SRC_PORT,DST_IP_ADDR,DST_IP_ADDR_HIGH,DST_PORT,VIRTUAL_SEGMENT_INDEX,PHYSICAL_PORT_IN,VLAN_TAG,SEVERITY,PACKET_TRACE,DEVICE_TRACE_BUCKET,DEVICE_TRACE_BEGIN_SEQ,DEVICE_TRACE_END_SEQ,MESSAGE_PARMS,IDX,QUARANTINE_ACTION,FLOW_CONTROL,ACTION_SET_UUID,ACTION_SET_NAME,RATE_LIMIT_RATE,CLIENT_IP_ADDR,XFF_IP_ADDR,TCIP_IP_ADDR,URI_METHOD,URI_HOST,URI_STRING,SRC_USER_NAME,SRC_DOMAIN,SRC_MACHINE,DST_USER_NAME,DST_DOMAIN,DST_MACHINE FROM SIGNATURE"
	return s.iterateTable(query, where, func(rows *sql.Rows) error {
		var a Alert
		         int64
		       int
		         uint16
		            sql.NullString
		         sql.NullString
		BeginTime           int64
		EndTime             int64
		HitCount            int
		SrcIpAddr           int64
		SrcIpAddrHigh       int64
		SrcPort             uint16
		DstIpAddr           int64
		DstIpAddrHigh       int64
		DstPort             uint16
		VirtualSegmentIndex int
		PhysicalPortIn      uint16
		VlanTag             uint16
		Severity            uint8
		PacketTrace         uint8
		DeviceTraceBucket   int
		DeviceTraceBeginSeq int
		DeviceTraceEndSeq   int
		MessageParms        sql.NullString
		Idx                 uint64
		QuarantineAction    sql.NullString
		FlowControl         sql.NullString
		ActionSetUuid       sql.NullString
		ActionSetName       sql.NullString
		RateLimitRate       sql.NullString
		ClientIpAddr        [16]byte
		XffIpAddr           [16]byte
		TcipIpAddr          [16]byte
		UriMethod           sql.NullString
		UriHost             sql.NullString
		UriString           sql.NullString
		SrcUserName         sql.NullString
		SrcDomain           sql.NullString
		SrcMachine          sql.NullString
		DstUserName         sql.NullString
		DstDomain           sql.NullString
		DstMachine          sql.NullString
		err := rows.Scan(&a.SequenceNum, &a.DeviceShortId, &a.AlertTypeId, &a.PolicyId, &a.SignatureId, &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., &a., )
		if err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		if err := callback(&s); err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		return nil
	})
}
*/

func (s *SMSDB) ListViews() error {
	query := `SELECT * FROM information_schema.views`
	rows, err := s.db.Query(query) // AND table_schema = ExternalAccess
	if err != nil {
		return fmt.Errorf("sql.Query: %w", err)
	}
	defer rows.Close()
	if rows.Err() != nil {
		return fmt.Errorf("rows.Err: %w", rows.Err())
	}
	for rows.Next() {
		var v [11]sql.NullString
		err := rows.Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10])
		if err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		fmt.Println("v=", v)
	}
	return nil
}

type ViewFields struct {
	Field   string
	Type    string
	Null    string
	Key     string
	Default sql.NullString
	Extra   sql.NullString
}

func (s *SMSDB) IterateViewFields(viewName string, callback func(viewFields *ViewFields) error) error {
	query := "SHOW COLUMNS FROM " + viewName
	//fmt.Println(query)
	return s.iterateTable(query, "", func(rows *sql.Rows) error {
		var v ViewFields
		err := rows.Scan(&v.Field, &v.Type, &v.Null, &v.Key, &v.Default, &v.Extra)
		if err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		if err := callback(&v); err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		return nil
	})
}

type View struct {
	Name string
	Type string
}

func (s *SMSDB) IterateViews(callback func(view *View) error) error {
	query := "SHOW FULL TABLES WHERE Table_Type LIKE 'VIEW'"
	return s.iterateTable(query, "", func(rows *sql.Rows) error {
		var v View
		err := rows.Scan(&v.Name, &v.Type)
		if err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		if err := callback(&v); err != nil {
			return fmt.Errorf("rows.Scan: %w", err)
		}
		return nil
	})
}

/*
	_ = `create table scientist (id integer, firstname varchar(100), lastname varchar(100));
	insert into scientist (id, firstname, lastname) values (1, 'albert', 'einstein');
	insert into scientist (id, firstname, lastname) values (2, 'isaac', 'newton');
	insert into scientist (id, firstname, lastname) values (3, 'marie', 'curie');
	SHOW COLUMNS FROM scientist;
	CREATE VIEW sview AS SELECT firstname AS fn FROM scientist;
	SELECT * FROM sview;
	SHOW FULL TABLES WHERE Table_Type LIKE 'VIEW';
	`
*/

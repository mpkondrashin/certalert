package sms

import (
	"fmt"
	"strings"
)

type BackupDatabaseOptions struct {
	Type           string
	Location       string
	Username       string
	Password       string
	Domain         string
	TOS            int
	DV             int
	Events         bool
	SSLPrivateKeys bool
	Notify         bool
	Timestamp      bool
	EncryptionPass string
}

func NewBackupDatabaseOptionsSMB(location, username, password, domain string) *BackupDatabaseOptions {
	return &BackupDatabaseOptions{
		Type:      "smb",
		Location:  location,
		Username:  username,
		Password:  password,
		Domain:    domain,
		Timestamp: true,
	}
}

func NewBackupDatabaseOptionsNFS(location string) *BackupDatabaseOptions {
	return &BackupDatabaseOptions{
		Type:      "nfs",
		Location:  location,
		Timestamp: true,
	}
}

func NewBackupDatabaseOptionsSCP(location, username, password string) *BackupDatabaseOptions {
	return &BackupDatabaseOptions{
		Type:      "scp",
		Location:  location,
		Username:  username,
		Password:  password,
		Timestamp: true,
	}
}

func NewBackupDatabaseOptionsSFTP(location, username, password string) *BackupDatabaseOptions {
	return &BackupDatabaseOptions{
		Type:      "sftp",
		Location:  location,
		Username:  username,
		Password:  password,
		Timestamp: true,
	}
}

func NewBackupDatabaseOptionsSMS() *BackupDatabaseOptions {
	return &BackupDatabaseOptions{
		Type:      "sms",
		Timestamp: true,
	}
}

func (b *BackupDatabaseOptions) SetTOS(tos int) *BackupDatabaseOptions {
	b.TOS = tos
	return b
}

func (b *BackupDatabaseOptions) SetDV(dv int) *BackupDatabaseOptions {
	b.DV = dv
	return b
}

func (b *BackupDatabaseOptions) SetEvents(flag bool) *BackupDatabaseOptions {
	b.Events = flag
	return b
}

func (b *BackupDatabaseOptions) SetSSLPrivateKeys(flag bool) *BackupDatabaseOptions {
	b.SSLPrivateKeys = flag
	return b
}
func (b *BackupDatabaseOptions) SetNotify(flag bool) *BackupDatabaseOptions {
	b.Notify = flag
	return b
}

func (b *BackupDatabaseOptions) SetTimestamp(flag bool) *BackupDatabaseOptions {
	b.Timestamp = flag
	return b
}

func (b *BackupDatabaseOptions) SetEncryptionPass(pass string) *BackupDatabaseOptions {
	b.EncryptionPass = pass
	return b
}

func (b *BackupDatabaseOptions) String() string {
	var url strings.Builder
	url.WriteString(fmt.Sprintf("/smsAdmin/backup?type=%s", b.Type))
	if b.Location != "" {
		url.WriteString(fmt.Sprintf("&location=%s", b.Location))
	}
	if b.Username != "" {
		url.WriteString(fmt.Sprintf("&username=%s", b.Username))
	}
	if b.Password != "" {
		url.WriteString(fmt.Sprintf("&password=%s", b.Password))
	}
	if b.Domain != "" {
		url.WriteString(fmt.Sprintf("&domain=%s", b.Domain))
	}
	if b.TOS > 0 {
		url.WriteString(fmt.Sprintf("&tos=%d", b.TOS))
	}
	if b.DV > 1 {
		url.WriteString(fmt.Sprintf("&dv=%d", b.DV))
	}
	if b.Events {
		url.WriteString("&events=true")
	}
	if b.SSLPrivateKeys {
		url.WriteString("&sslPrivateKeys=true")
	}
	if b.Notify {
		url.WriteString("&notify=true")
	}
	if !b.Timestamp {
		url.WriteString("&timestamp=false")
	}
	if b.EncryptionPass != "" {
		url.WriteString(fmt.Sprintf("&encryptionPass=%s", b.EncryptionPass))
	}
	return url.String()
}

func (s *SMS) BackupDatabase(options *BackupDatabaseOptions) error {
	err := s.SendRequest("GET", options.String(), nil, nil)
	if err != nil {
		return fmt.Errorf("BackupDatabase: %w", err)
	}
	return nil
}

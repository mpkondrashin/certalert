package certs

import (
	"archive/tar"
	"archive/zip"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

var ErrNotFound = errors.New("not found")

type X509Certificate struct {
	ID              string `xml:"id,attr"`
	Name            string `xml:"name,attr"`
	Ca              string `xml:"ca,attr"`
	Exportable      string `xml:"exportable,attr"`
	ThumbPrint      string `xml:"thumbPrint,attr"`
	CertificateData string `xml:"certificate-data"`
}

type X509Certificates struct {
	XMLName         xml.Name          `xml:"x509-certificates"`
	X509Certificate []X509Certificate `xml:"x509-certificate"`
}

func SeekFor(tarReader *tar.Reader, fileName string) error {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return fmt.Errorf("%s: %w", fileName, ErrNotFound)
		}
		if header.Name == fileName {
			return nil
		}
	}
}

func IterateFileFromTar(tarReader *tar.Reader, pattern string, callback func(io.Reader) error) error {
	count := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if header.FileInfo().IsDir() {
			continue
		}
		matched, err := filepath.Match(pattern, header.Name)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		err = callback(tarReader)
		if err == ErrNotFound {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", header.Name, err)
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("%s: %w", pattern, ErrNotFound)
	}
	return nil
}

func GetFileFromZip(input io.ReaderAt, length int64, fileName string) (io.ReadCloser, error) {
	zipReader, err := zip.NewReader(input, length)
	if err != nil {
		return nil, err
	}
	for _, z := range zipReader.File {
		if z.Name != fileName {
			continue
		}
		f, err := z.Open()
		if err != nil {
			return nil, fmt.Errorf("%s: Open %s: %w", fileName, z.Name, err)
		}
		return f, nil

	}
	return nil, fmt.Errorf("%s: %w", fileName, ErrNotFound)
}

func Iterate(smsBackupFileName string, callback func(*x509.Certificate) error) error {
	info, err := os.Stat(smsBackupFileName)
	if err != nil {
		log.Fatal(err)
	}
	zipFile, err := os.Open(smsBackupFileName)
	if err != nil {
		log.Fatal(err)
	}
	SMSConfigTAR, err := GetFileFromZip(zipFile, info.Size(), "sms-config.tar")
	if err != nil {
		log.Fatal(fmt.Errorf("%s: %w", smsBackupFileName, err))
	}
	defer SMSConfigTAR.Close()
	folderMask := "opt/sms/policy/images/*"
	return IterateFileFromTar(tar.NewReader(SMSConfigTAR), folderMask,
		func(input io.Reader) error {
			tarReader := tar.NewReader(input)
			err := SeekFor(tarReader, "x509-certificates.xml")
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					return ErrNotFound
				}
				return err
			}
			decoder := xml.NewDecoder(tarReader)
			var x509Certs X509Certificates
			err = decoder.Decode(&x509Certs)
			if err != nil {
				return err
			}
			for _, each := range x509Certs.X509Certificate {
				block, _ := pem.Decode([]byte(each.CertificateData))
				if block == nil {
					return fmt.Errorf("failed to parse certificate PEM")
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %v", err)
				}
				if err := callback(cert); err != nil {
					return err
				}
			}
			return nil
		})
}

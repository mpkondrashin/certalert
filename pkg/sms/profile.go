package sms

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

type ProfileFile struct {
	path string
}

func NewProfileFile(path string) *ProfileFile {
	return &ProfileFile{
		path: path,
	}
}

func (p *ProfileFile) ProcessXMLInProfileFile(targetFile, fileName string, data interface{}, callback func() error) error {
	f, err := os.Open(p.path)
	if err != nil {
		return err
	}
	defer f.Close()
	tarReader := tar.NewReader(f)
	fileOut, err := os.Create(targetFile)
	if err != nil {
		return err
	}
	tarWriter := tar.NewWriter(fileOut)
	manifest := NewManifestFile()
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if header.Typeflag != tar.TypeReg {
			//fmt.Println("not file: ", header.Name)
			// Empty folders will be removed
			return nil
		}
		//fmt.Println("Processing: ", header.Name)
		fileNameInTar := strings.TrimLeft(header.Name, "./")
		if fileNameInTar == fileName {
			xmlData := new(bytes.Buffer)
			_, err = xmlData.ReadFrom(tarReader)
			if err != nil {
				return err
			}
			err := xml.Unmarshal(xmlData.Bytes(), data)
			if err != nil {
				return err
			}
			err = callback()
			if err != nil {
				return callback()
			}
			resultXML, err := xml.Marshal(data)
			if err != nil {
				return err
			}
			header.Size = int64(len(resultXML))
			header.ModTime = time.Now()
			err = tarWriter.WriteHeader(header)
			if err != nil {
				return err
			}
			_, err = tarWriter.Write(resultXML)
			if err != nil {
				return err
			}
			manifest.AddFile(fileName, resultXML)
			continue
		}
		if fileNameInTar == ManifestFileName {
			// We will add it in the end
			continue
		}
		tarWriter.WriteHeader(header)
		hash := md5.New()
		tee := io.TeeReader(tarReader, hash)
		_, err = io.Copy(tarWriter, tee)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		manifest.AddHash(fileNameInTar, hash.Sum(nil))
	}
	manifest.WriteTar(tarWriter)
	return nil
}

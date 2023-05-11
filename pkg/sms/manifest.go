package sms

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"fmt"
	"time"
)

const ManifestFileName = "sms-security-manifest"

type ManifestFile struct {
	hashes map[string][]byte
}

func NewManifestFile() *ManifestFile {
	return &ManifestFile{
		hashes: make(map[string][]byte),
	}
}

func (m *ManifestFile) AddHash(fileName string, hash []byte) {
	//	fmt.Println("AddHash", fileName, hash)
	m.hashes[fileName] = hash
}

func (m *ManifestFile) AddFile(fileName string, content []byte) {
	//	fmt.Println("AddFile", fileName, string(content))
	h := md5.Sum(content)
	m.hashes[fileName] = h[:]
}

func (m *ManifestFile) Contents() []byte {
	var b bytes.Buffer
	for fileName, hash := range m.hashes {
		//	fmt.Println("contents ", fileName, hash)
		b.WriteString(fmt.Sprintf("%x", hash))
		b.WriteString("  ")
		b.WriteString(fileName)
		b.WriteString("\n")
	}
	return b.Bytes()
	/*
		No need for sms-security-manifest itself
		manifestHash := md5.Sum(b.Bytes())
		b.WriteString(fmt.Sprintf("%x", manifestHash))
		b.WriteString("  ")
		b.WriteString(ManifestFileName)
		b.WriteString("\n")
		return b.Bytes()
	*/
}

func (m *ManifestFile) WriteTar(tarWriter *tar.Writer) error {
	contents := m.Contents()
	//	fmt.Println("WiteTar:", string(contents))
	h := tar.Header{
		Name:    ManifestFileName,
		Size:    int64(len(contents)),
		Mode:    0o644,
		ModTime: time.Now(),
	}
	err := tarWriter.WriteHeader(&h)
	if err != nil {
		return err
	}
	_, err = tarWriter.Write(contents)
	return err
}

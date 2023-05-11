package sms

import (
	"archive/tar"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func CreateProfileFile(t *testing.T) string {
	testingFolder := "testing_sms"
	err := os.RemoveAll(testingFolder)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	err = os.MkdirAll(testingFolder, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	tarballFileName := "profile.tar"
	tarballFilePath := filepath.Join(testingFolder, tarballFileName)
	file, err := os.Create(tarballFilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	tarWriter := tar.NewWriter(file)
	defer tarWriter.Close()

	data := []struct {
		name    string
		content string
	}{
		{"a.xml", "<a>A</a>"},
		{"b.xml", "<b>B</b>"},
	}

	for _, each := range data {
		header := &tar.Header{
			Name:    each.name,
			Size:    int64(len(each.content)),
			Mode:    0o644,
			ModTime: time.Now(),
		}

		err = tarWriter.WriteHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tarWriter.Write([]byte(each.content))
		if err != nil {
			t.Fatal(err)
		}
	}
	return tarballFilePath
}

type A struct {
	XMLName xml.Name `xml:"a"`
	Text    string   `xml:",chardata"`
}

func TestProcessXMLInPolicyFile(t *testing.T) {
	tarballFilePath := CreateProfileFile(t)
	p := NewProfileFile(tarballFilePath)
	changedTar := filepath.Join(filepath.Dir(tarballFilePath), "changed.tar")
	newData := "DDD"
	var a A
	err := p.ProcessXMLInProfileFile(
		changedTar,
		"a.xml",
		&a,
		func() error {
			expect := "A"
			if a.Text != expect {
				t.Fatalf("%s != %s", expect, a.Text)
			}
			a.Text = newData
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return
	q := NewProfileFile(changedTar)
	err = q.ProcessXMLInProfileFile(
		tarballFilePath,
		"a.xml",
		&a,
		func() error {
			expect := newData
			if a.Text != expect {
				t.Fatalf("%s != %s", expect, a.Text)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTBCheck(t *testing.T) {
	p := NewProfileFile("tbcheck2.pkg")
	changedTar := filepath.Join(filepath.Dir("."), "tbcheck2_changed.pkg")
	//newData := "DDD"
	var policies Policies
	err := p.ProcessXMLInProfileFile(
		changedTar,
		"policies.xml",
		&policies,
		func() error {
			for n, p := range policies.Policy {
				fmt.Printf("%d: [%s] I: %s R: %s\n", n, p.ID,
					p.Base.Actionset.Indirect, p.Base.Actionset.Refid)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}

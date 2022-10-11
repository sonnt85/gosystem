package pidfile

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAndRemove(t *testing.T) {
	dir, err := ioutil.TempDir(os.TempDir(), "test-pidfile")
	if err != nil {
		t.Fatal("Could not create test directory")
	}

	path := filepath.Join(dir, "testfile")
	file, err := New(path, nil)
	if err != nil {
		t.Fatal("Could not create test file", err)
	}

	_, err = New(path, nil)
	if err == nil {
		t.Fatal("Test file creation not blocked")
	}

	if err := file.Remove(); err != nil {
		t.Fatal("Could not delete created test file")
	}

	if err := os.Remove(dir); err != nil {
		t.Fatal("Could not delete test dir")
	}
}

func TestRemoveInvalidPath(t *testing.T) {
	file := Pidfile{path: filepath.Join("foo", "bar")}

	if err := file.Remove(); err == nil {
		t.Fatal("Non-existing file doesn't give an error on delete")
	}
}

func TestNew(t *testing.T) {
	f, err := New("data/aa.pid", []byte("123"))
	require.Nil(t, err)
	fmt.Println(f.Map["pid"])

}

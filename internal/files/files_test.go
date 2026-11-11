package files

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTraversalAndSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	_ = os.MkdirAll(root, 0o755)
	_ = os.MkdirAll(outside, 0o755)
	_ = os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	m := New([]string{root})

	if err := m.Write(filepath.Join(root, "a.txt"), "hello"); err != nil {
		t.Fatal(err)
	}
	if s, err := m.Read(filepath.Join(root, "a.txt")); err != nil || s != "hello" {
		t.Fatalf("read: %q %v", s, err)
	}
	for _, p := range []string{
		filepath.Join(root, "..", "outside", "secret"),
		filepath.Join(root, "link", "secret"),
		filepath.Join(root, "link", "new"),
		"relative/path",
		"/etc/passwd",
	} {
		if _, err := m.Read(p); err == nil {
			t.Errorf("read %q must be denied", p)
		}
		if err := m.Write(p, "x"); err == nil {
			t.Errorf("write %q must be denied", p)
		}
	}
	if err := m.Delete(root); err == nil {
		t.Error("deleting the root must be denied")
	}
	if err := m.Upload(root, "../evil", nil); err == nil {
		t.Error("upload with traversal name must be denied")
	}
}

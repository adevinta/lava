// Copyright 2023 Adevinta

package initialize

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRun(t *testing.T) {
	oldCfgfile := *cfgfile
	defer func() { *cfgfile = oldCfgfile }()

	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	*cfgfile = filepath.Join(tmpPath, "lava.yaml")

	if err := run(nil); err != nil {
		t.Fatalf("run error: %v", err)
	}

	data, err := os.ReadFile(*cfgfile)
	if err != nil {
		t.Fatalf("error reading file: %v", err)
	}

	if slices.Compare(data, defaultConfig) != 0 {
		t.Errorf("unexpected data:\ngot:\n%s\nwant:\n%s", data, defaultConfig)
	}
}

func TestRun_force(t *testing.T) {
	oldCfgfile := *cfgfile
	oldForce := *force
	defer func() {
		*cfgfile = oldCfgfile
		*force = oldForce
	}()

	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	*cfgfile = filepath.Join(tmpPath, "lava.yaml")

	if err := os.WriteFile(*cfgfile, []byte("test"), 0644); err != nil {
		t.Fatalf("error writing file: %v", err)
	}

	*force = true
	if err := run(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(*cfgfile)
	if err != nil {
		t.Fatalf("error reading file: %v", err)
	}

	if slices.Compare(data, defaultConfig) != 0 {
		t.Errorf("unexpected data:\ngot:\n%s\nwant:\n%s", data, defaultConfig)
	}
}

func TestRun_file_exists(t *testing.T) {
	oldCfgfile := *cfgfile
	defer func() { *cfgfile = oldCfgfile }()

	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	*cfgfile = filepath.Join(tmpPath, "lava.yaml")

	if err := os.WriteFile(*cfgfile, []byte("test"), 0644); err != nil {
		t.Fatalf("error writing file: %v", err)
	}

	if err := run(nil); !errors.Is(err, fs.ErrExist) {
		t.Errorf("unexpected error: %v", err)
	}
}

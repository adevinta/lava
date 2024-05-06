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

func TestRunInit(t *testing.T) {
	oldInitC := initC
	defer func() { initC = oldInitC }()

	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	initC = filepath.Join(tmpPath, "lava.yaml")

	if err := runInit(nil); err != nil {
		t.Fatalf("run error: %v", err)
	}

	data, err := os.ReadFile(initC)
	if err != nil {
		t.Fatalf("error reading file: %v", err)
	}

	if slices.Compare(data, defaultConfig) != 0 {
		t.Errorf("unexpected data:\ngot:\n%s\nwant:\n%s", data, defaultConfig)
	}
}

func TestRunInit_force(t *testing.T) {
	oldInitC := initC
	oldInitF := initF
	defer func() {
		initC = oldInitC
		initF = oldInitF
	}()

	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	initC = filepath.Join(tmpPath, "lava.yaml")

	if err := os.WriteFile(initC, []byte("test"), 0644); err != nil {
		t.Fatalf("error writing file: %v", err)
	}

	initF = true
	if err := runInit(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(initC)
	if err != nil {
		t.Fatalf("error reading file: %v", err)
	}

	if slices.Compare(data, defaultConfig) != 0 {
		t.Errorf("unexpected data:\ngot:\n%s\nwant:\n%s", data, defaultConfig)
	}
}

func TestRunInit_file_exists(t *testing.T) {
	oldInitC := initC
	defer func() { initC = oldInitC }()

	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	initC = filepath.Join(tmpPath, "lava.yaml")

	if err := os.WriteFile(initC, []byte("test"), 0644); err != nil {
		t.Fatalf("error writing file: %v", err)
	}

	if err := runInit(nil); !errors.Is(err, fs.ErrExist) {
		t.Errorf("unexpected error: %v", err)
	}
}

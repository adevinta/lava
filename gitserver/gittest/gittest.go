// Copyright 2023 Adevinta

// Package gittest provides utilities for Git testing.
package gittest

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

// CloneTemp clones the specified local repository into a temporary
// directory. It returns the temporary directory.
func CloneTemp(path string) (tmpPath string, err error) {
	tmpPath, err = os.MkdirTemp("", "")
	if err != nil {
		return "", fmt.Errorf("make temp dir: %w", err)
	}
	defer func() {
		if err != nil {
			if rmErr := os.RemoveAll(tmpPath); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("remove temp dir %s: %w", path, rmErr))
			}
		}
	}()

	buf := &bytes.Buffer{}
	cmd := exec.Command("git", "clone", path, tmpPath)
	cmd.Stderr = buf
	if err = cmd.Run(); err != nil {
		return "", fmt.Errorf("git clone %v: %w: %q", path, err, buf)
	}

	return tmpPath, nil
}

// ExtractTemp extracts the provided tar archive into a temporary
// directory. It returns the temporary directory. Test repositories
// are distributed as tar files.
func ExtractTemp(tarfile string) (tmpPath string, err error) {
	tmpPath, err = os.MkdirTemp("", "")
	if err != nil {
		return "", fmt.Errorf("make temp dir: %w", err)
	}
	defer func() {
		if err != nil {
			if rmErr := os.RemoveAll(tmpPath); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("remove temp dir %s: %w", tmpPath, rmErr))
			}
		}
	}()

	if err = untar(tarfile, tmpPath); err != nil {
		return "", fmt.Errorf("untar test repository: %w", err)
	}

	return tmpPath, nil
}

// untar extracts the specified tar file into path.
func untar(tarfile string, path string) error {
	f, err := os.Open(tarfile)
	if err != nil {
		return fmt.Errorf("open tar file: %w", err)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// End of archive.
			break
		}
		if err != nil {
			return fmt.Errorf("next entry: %w", err)
		}

		target := filepath.Join(path, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("create dir: %w", err)
			}
		case tar.TypeReg:
			if err = writeFile(target, fs.FileMode(hdr.Mode), tr); err != nil {
				return fmt.Errorf("create file: %w", err)
			}
		default:
			return fmt.Errorf("unexpected type flag: %v", hdr.Typeflag)
		}
	}

	return nil
}

// writeFile writes the data from the reader to the named file until
// EOF is reached, creating the file if necessary. If the file does
// not exist, writeFile creates it with permissions perm (before
// umask); otherwise writeFile truncates it before writing, without
// changing permissions.
func writeFile(name string, mode fs.FileMode, r io.Reader) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, mode)
	if err != nil {
		return fmt.Errorf("open destination file: %w", err)
	}
	defer f.Close()

	if _, err = io.Copy(f, r); err != nil {
		return fmt.Errorf("write file contents: %w", err)
	}
	return nil
}

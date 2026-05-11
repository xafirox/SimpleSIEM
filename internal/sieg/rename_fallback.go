package sieg

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// safeRenameDir is os.Rename with a copy+remove fallback for the case
// where the underlying filesystem refuses cross-volume / cross-mount
// renames with EXDEV. This shows up most often in two situations:
//
//  1. Docker overlayfs without the `redirect_dir` mount option:
//     renaming a directory that originated in a lower image layer
//     fails with EXDEV even though both paths are on the same overlay.
//     The shell `mv` command falls back to a copy in that situation;
//     Go's os.Rename surfaces the raw EXDEV. Our restore needs the
//     same fall-through behaviour or it can't promote staging trees
//     into the install paths the operator (or a Dockerfile RUN
//     install -d) created during image build.
//
//  2. Truly cross-mount renames — `<log_dir>` lives on a separate
//     volume from `<config_dir>` etc. The fallback handles that
//     case identically.
//
// On any non-EXDEV error the original error is returned unchanged so
// permission errors, missing-source errors, etc. surface verbatim
// without being masked by the copy path.
func safeRenameDir(src, dst string) error {
	// Windows-only: retry the rename a few times with short backoff.
	// MoveFileEx can return ERROR_ACCESS_DENIED / ERROR_SHARING_VIOLATION /
	// ERROR_FILE_NOT_FOUND for up to ~1s after a daemon stop while the
	// kernel finishes flushing handles inside the directory tree. The
	// retry window is short and bounded so a real "source missing" or
	// "permission denied" still surfaces in a reasonable time.
	var err error
	attempts := 1
	if runtime.GOOS == "windows" {
		attempts = 6
	}
	for i := 0; i < attempts; i++ {
		err = os.Rename(src, dst)
		if err == nil {
			return nil
		}
		// EXDEV must skip the retry loop and go straight to the copy
		// fallback below — retrying won't help cross-mount renames.
		if isCrossDevice(err) {
			break
		}
		// On non-Windows or on the last Windows attempt, surface the
		// error verbatim without paying the retry cost.
		if i == attempts-1 {
			break
		}
		time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
	}
	if err != nil && !isCrossDevice(err) {
		return err
	}
	if err := copyDirContents(src, dst); err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	return os.RemoveAll(src)
}

// isCrossDevice unwraps a returned error and reports whether the
// underlying syscall error was EXDEV. Both *os.PathError and
// *os.LinkError can wrap it depending on which operation produced it.
func isCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV)
}

// copyDirContents copies an entire directory tree from src to dst.
// dst is created at src's permissions; intermediate dirs and regular
// files are copied; symlinks are reproduced as symlinks (we don't
// chase them, same as the backup tarball writer).
func copyDirContents(src, dst string) error {
	return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, fi.Mode().Perm())
		}
		target := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, fi.Mode().Perm())
		case fi.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		default:
			return copyOneFile(path, target, fi.Mode().Perm())
		}
	})
}

func copyOneFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

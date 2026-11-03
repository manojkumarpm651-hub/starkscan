// Command mktarball builds a .tar.gz for release packaging.
//
// It exists because the tar shipped with Windows (bsdtar) cannot set entry
// modes, so an archive built with it hands Linux and macOS recipients a
// binary they have to chmod before it will run.
//
// Entries are written with fixed ownership and a fixed timestamp as well as
// explicit modes, so building the same inputs twice produces a byte-identical
// archive. For a security tool that recipients are asked to verify by hash,
// being able to reproduce the artifact is worth more than preserving the
// build machine's mtimes.
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	var (
		out      = flag.String("out", "", "path of the .tar.gz to write")
		root     = flag.String("root", "", "directory containing the package folder")
		name     = flag.String("name", "", "package folder name inside root, also the archive's top-level directory")
		execName = flag.String("exec", "", "file within the package to mark executable")
		epoch    = flag.String("epoch", "", "fixed entry timestamp, RFC3339 (default: 2000-01-01T00:00:00Z)")
	)
	flag.Parse()

	if *out == "" || *root == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "mktarball: -out, -root and -name are required")
		os.Exit(2)
	}

	stamp := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if *epoch != "" {
		t, err := time.Parse(time.RFC3339, *epoch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mktarball: -epoch: %v\n", err)
			os.Exit(2)
		}
		stamp = t
	}

	if err := build(*out, *root, *name, *execName, stamp); err != nil {
		fmt.Fprintf(os.Stderr, "mktarball: %v\n", err)
		os.Exit(1)
	}
}

func build(out, root, name, execName string, stamp time.Time) error {
	pkgDir := filepath.Join(root, name)
	if _, err := os.Stat(pkgDir); err != nil {
		return err
	}

	// Collect and sort first: filesystem walk order is not guaranteed, and a
	// reproducible archive needs a deterministic entry order.
	var rel []string
	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == pkgDir {
			return nil
		}
		r, err := filepath.Rel(pkgDir, p)
		if err != nil {
			return err
		}
		rel = append(rel, filepath.ToSlash(r))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(rel)

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	// The top-level directory every entry lives under, so extracting never
	// scatters files into the recipient's current directory.
	if err := tw.WriteHeader(&tar.Header{
		Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: stamp,
		Uid: 0, Gid: 0, Uname: "root", Gname: "root",
	}); err != nil {
		return err
	}

	for _, r := range rel {
		full := filepath.Join(pkgDir, r)
		info, err := os.Lstat(full)
		if err != nil {
			return err
		}

		hdr := &tar.Header{
			Name:    name + "/" + r,
			ModTime: stamp,
			Uid:     0, Gid: 0, Uname: "root", Gname: "root",
		}

		switch {
		case info.IsDir():
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			hdr.Mode = 0o755
		case info.Mode().IsRegular():
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
			// Only the named binary is executable; documentation is not.
			if execName != "" && strings.EqualFold(r, execName) {
				hdr.Mode = 0o755
			} else {
				hdr.Mode = 0o644
			}
		default:
			// Symlinks and specials have no place in a release package.
			return fmt.Errorf("%s: unsupported file type %v", r, info.Mode())
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		src, err := os.Open(full)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, src); err != nil {
			src.Close()
			return err
		}
		src.Close()
	}
	return nil
}

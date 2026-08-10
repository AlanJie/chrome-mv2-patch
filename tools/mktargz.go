//go:build ignore

// mktargz writes the Linux release tarball for build.bat.
//
// It exists because there is no portable `tar` on a Windows build host. Which
// one runs depends on a PATH race: Windows 10+ ships bsdtar (libarchive) in
// System32, Git for Windows ships GNU tar in usr\bin. Only GNU tar accepts
// --mode / --sort, and only --mode can restore the execute bit that a
// Windows-staged file has no way to carry, so the tarball's chrome-mv2 would
// otherwise extract non-executable (bsdtar records 0666 from the NTFS mode).
//
// Writing the archive here instead needs nothing build.bat doesn't already
// require - the Go toolchain checked in step 0 - and records the modes and the
// entry order exactly rather than inheriting them from the host filesystem.
//
// Usage:
//
//	go run tools/mktargz.go -o <out.tar.gz> -C <dir> [-exec a,b] <member>...
//
// Members are named explicitly (never globbed) so a stray file in the staging
// directory cannot slip into a release. Anything listed in -exec is recorded
// 0755, everything else 0644.
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	out := flag.String("o", "", "output .tar.gz path (required)")
	dir := flag.String("C", ".", "directory the members are read from")
	exec := flag.String("exec", "", "comma-separated members to record as mode 0755")
	flag.Parse()

	if err := build(*out, *dir, *exec, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "mktargz:", err)
		// Never leave a half-written archive behind for the release step to
		// pick up; a missing file is a clearer failure than a truncated one.
		if *out != "" {
			os.Remove(*out)
		}
		os.Exit(1)
	}
}

func build(out, dir, execList string, members []string) error {
	if out == "" {
		return fmt.Errorf("-o is required")
	}
	if len(members) == 0 {
		return fmt.Errorf("no members given")
	}

	executable := make(map[string]bool)
	for _, name := range strings.Split(execList, ",") {
		if name = strings.TrimSpace(name); name != "" {
			executable[name] = true
		}
	}

	// Stable entry order no matter how the caller ordered its arguments - the
	// equivalent of GNU tar's --sort=name, so two builds of the same tree
	// produce the same archive layout.
	members = append([]string(nil), members...)
	sort.Strings(members)

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)

	for _, name := range members {
		if err := addFile(tw, dir, name, executable[name]); err != nil {
			return err
		}
	}

	// Closed innermost-first and checked: the tar footer and the gzip trailer
	// are both written at Close, so a dropped error here means a corrupt
	// archive that every other step would still treat as a success.
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

// addFile appends one regular file from dir as a flat archive member.
func addFile(tw *tar.Writer, dir, name string, isExec bool) error {
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", name)
	}

	mode := int64(0o644)
	if isExec {
		mode = 0o755
	}

	// USTAR keeps the archive readable by anything; it stores whole seconds
	// only, so the mtime is truncated rather than left to fail encoding.
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name, // flat tree: no separator to normalise
		Size:     fi.Size(),
		Mode:     mode,
		ModTime:  fi.ModTime().Truncate(time.Second),
		Uname:    "root",
		Gname:    "root",
		Format:   tar.FormatUSTAR,
	}); err != nil {
		return err
	}

	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	_, err = io.Copy(tw, src)
	return err
}

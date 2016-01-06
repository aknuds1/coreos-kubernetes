package blobutil

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func MustReadAndCompressFile(loc string) string {
	f, err := os.Open(loc)
	if err != nil {
		stderr("Failed opening file %s: %v", loc, err)
		os.Exit(1)
	}
	defer f.Close()

	buf := &bytes.Buffer{}

	b64Writer := base64.NewEncoder(base64.StdEncoding, buf)

	gzWriter, err := gzip.NewWriterLevel(b64Writer, gzip.BestCompression)
	if err != nil {
		stderr("Failed creating gzip context: %v", err)
		os.Exit(1)
	}

	if _, err := io.Copy(gzWriter, f); err != nil {
		stderr("Failed reading file %s: %v", loc, err)
		os.Exit(1)
	}

	gzWriter.Close()
	b64Writer.Close()
	return buf.String()
}

func stderr(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
}

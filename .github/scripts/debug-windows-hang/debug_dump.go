// This file is copied into $GOROOT/src/cmd/go to build a go command that
// can report where it is stuck. When GO_DEBUG_DUMP_DIR is set, the command
// writes every goroutine's stack to that directory each time the file
// "dump" there is created or modified.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"
)

func init() {
	dir := os.Getenv("GO_DEBUG_DUMP_DIR")
	if dir == "" {
		return
	}
	go func() {
		trigger := filepath.Join(dir, "dump")
		var handled time.Time
		for n := 1; ; time.Sleep(5 * time.Second) {
			fi, err := os.Stat(trigger)
			if err != nil || !fi.ModTime().After(handled) {
				continue
			}
			handled = fi.ModTime()
			name := filepath.Join(dir, fmt.Sprintf("go-%d-%d.txt", os.Getpid(), n))
			n++
			f, err := os.Create(name)
			if err != nil {
				continue
			}
			_ = pprof.Lookup("goroutine").WriteTo(f, 2)
			_ = f.Close()
		}
	}()
}

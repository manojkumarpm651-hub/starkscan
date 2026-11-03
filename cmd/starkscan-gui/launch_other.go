//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
)

// launch is unavailable off Windows: the interface is built on Windows Forms.
// The stub exists so the whole module still builds and vets on every platform.
func launch(_ []string) error {
	return errors.New("the desktop interface is Windows-only; " +
		"use the starkscan command-line scanner instead")
}

func fail(msg string) { fmt.Fprintln(os.Stderr, "starkscan-gui:", msg) }

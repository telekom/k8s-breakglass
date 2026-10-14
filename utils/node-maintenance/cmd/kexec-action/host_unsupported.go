// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

package main

import (
	"errors"
	"os"
	"time"
)

var errUnsupported = errors.New("kexec recovery requires linux/amd64 or linux/arm64")

type hostSystem struct{}

func (hostSystem) readFile(string) ([]byte, error)      { return nil, errUnsupported }
func (hostSystem) open(string) (*os.File, error)        { return nil, errUnsupported }
func (hostSystem) snapshot(string) (*os.File, error)    { return nil, errUnsupported }
func (hostSystem) seal(*os.File) error                  { return errUnsupported }
func (hostSystem) kexecFileLoad(int, int, []byte) error { return errUnsupported }
func (hostSystem) kexecUnload() error                   { return errUnsupported }
func (hostSystem) sync()                                {}
func (hostSystem) ignoreTermination()                   {}
func (hostSystem) rebootKexec() error                   { return errUnsupported }
func (hostSystem) now() time.Time                       { return time.Now() }

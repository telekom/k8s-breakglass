// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

const tarBlockSize = int64(512)

type tarMember struct {
	name      string
	typeflag  byte
	size      int64
	directory bool
	extension bool
}

func parseTarHeader(header []byte) (tarMember, error) {
	var member tarMember
	if len(header) != int(tarBlockSize) {
		return member, errors.New("tar header has an invalid size")
	}
	if !bytes.Equal(header[257:265], []byte("ustar\x0000")) &&
		!bytes.Equal(header[257:265], []byte("ustar  \x00")) {
		return member, errors.New("tar header magic or version is invalid")
	}
	if err := verifyTarChecksum(header); err != nil {
		return member, err
	}
	name, err := tarString(header[0:100])
	if err != nil {
		return member, errors.New("tar member name padding is invalid")
	}
	prefix, err := tarString(header[345:500])
	if err != nil {
		return member, errors.New("tar member prefix padding is invalid")
	}
	if prefix != "" {
		name = prefix + "/" + name
	}
	size, err := parseTarNumber(header[124:136])
	if err != nil {
		return member, fmt.Errorf("tar size: %w", err)
	}
	if size < 0 {
		return member, errors.New("tar size is negative")
	}
	typeflag := header[156]
	member.name, member.typeflag, member.size = name, typeflag, size
	switch typeflag {
	case 0, '0':
	case '5':
		member.directory = true
	case 'L', 'x':
		member.extension = true
	case 'g', 'K':
		return member, errors.New("tar global or link extension is not accepted")
	default:
		return member, errors.New("tar link, sparse, device, FIFO, or special member is not accepted")
	}
	return member, nil
}

func verifyTarChecksum(header []byte) error {
	want, err := parseTarNumber(header[148:156])
	if err != nil {
		return errors.New("tar checksum is invalid")
	}
	var sum int64
	for index, value := range header {
		if index >= 148 && index < 156 {
			sum += int64(' ')
		} else {
			sum += int64(value)
		}
	}
	if sum != want {
		return errors.New("tar checksum does not match")
	}
	return nil
}

func parseTarNumber(field []byte) (int64, error) {
	field = bytes.Trim(field, "\x00 ")
	if len(field) == 0 {
		return 0, nil
	}
	if field[0]&0x80 != 0 {
		return 0, errors.New("base-256 tar numbers are not accepted")
	}
	var value int64
	for _, digit := range field {
		if digit < '0' || digit > '7' {
			return 0, errors.New("tar number is not octal")
		}
		if value > (maxInt64-int64(digit-'0'))/8 {
			return 0, errors.New("tar number overflows")
		}
		value = value*8 + int64(digit-'0')
	}
	return value, nil
}

func tarString(field []byte) (string, error) {
	if index := bytes.IndexByte(field, 0); index >= 0 {
		for _, value := range field[index+1:] {
			if value != 0 {
				return "", errors.New("tar string has nonzero padding")
			}
		}
		field = field[:index]
	}
	return string(field), nil
}

func paddedTarSize(size, maximum int64) (int64, error) {
	if size < 0 || size > maximum || size > maxInt64-tarBlockSize+1 {
		return 0, errors.New("tar member size is invalid")
	}
	return ((size + tarBlockSize - 1) / tarBlockSize) * tarBlockSize, nil
}

func tarRecordSize(contentPadded int64) (int64, error) {
	if contentPadded < 0 || contentPadded > maxInt64-tarBlockSize {
		return 0, errors.New("tar record size overflows")
	}
	return tarBlockSize + contentPadded, nil
}

func tarMemberEnd(padded, size, available int64) (int64, error) {
	if padded < tarBlockSize || size < 0 || size > padded-tarBlockSize || size > maxInt64-tarBlockSize {
		return 0, errors.New("tar member size is outside its padded record")
	}
	end := tarBlockSize + size
	if end > available {
		return 0, errors.New("tar member size exceeds its record")
	}
	return end, nil
}

func parseTarExtension(typeflag byte, content []byte, maxPathBytes int) (string, error) {
	switch typeflag {
	case 'L':
		nameEnd := bytes.IndexByte(content, 0)
		if nameEnd <= 0 || !allZero(content[nameEnd:]) {
			return "", errors.New("tar long-name extension is invalid")
		}
		name := string(content[:nameEnd])
		if len(name) > maxPathBytes || !printableASCII(name) {
			return "", errors.New("tar long-name extension is invalid")
		}
		return name, nil
	case 'x':
		var name string
		foundPath := false
		for len(content) > 0 {
			space := bytes.IndexByte(content, ' ')
			if space <= 0 || space >= len(content) {
				return "", errors.New("tar PAX extension is invalid")
			}
			for _, digit := range content[:space] {
				if digit < '0' || digit > '9' {
					return "", errors.New("tar PAX extension length is invalid")
				}
			}
			length, err := strconv.Atoi(string(content[:space]))
			if err != nil || length < space+3 || length > len(content) {
				return "", errors.New("tar PAX extension length is invalid")
			}
			record := content[:length]
			if record[length-1] != '\n' {
				return "", errors.New("tar PAX extension record is invalid")
			}
			equal := bytes.IndexByte(record[space+1:], '=')
			if equal < 0 {
				return "", errors.New("tar PAX extension record is invalid")
			}
			equal += space + 1
			key := string(record[space+1 : equal])
			if key != "path" || foundPath {
				return "", errors.New("tar PAX extension key is not accepted")
			}
			value := record[equal+1 : length-1]
			if len(value) == 0 || len(value) > maxPathBytes || bytes.IndexByte(value, 0) >= 0 ||
				!printableASCII(string(value)) {
				return "", errors.New("tar PAX extension path is invalid")
			}
			name = string(value)
			foundPath = true
			content = content[length:]
		}
		if !foundPath {
			return "", errors.New("tar PAX extension path is missing")
		}
		return name, nil
	default:
		return "", errors.New("tar extension is not accepted")
	}
}

func canonicalTarName(name string, directory bool, maxPathBytes int) (string, error) {
	if len(name) == 0 || len(name) > maxPathBytes || strings.ContainsRune(name, 0) ||
		strings.ContainsRune(name, '\\') || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "./") ||
		!printableASCII(name) {
		return "", errors.New("archive member path is invalid")
	}
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || path.Clean(name) != name || strings.Contains(name, "//") {
		return "", errors.New("archive member path is invalid")
	}
	return name, nil
}

func printableASCII(value string) bool {
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

const maxInt64 = int64(^uint64(0) >> 1)

package handler

import (
	"encoding/base64"
	"strings"
)

func MaybeDecode(value string) string {
	if strings.HasPrefix(value, "base64: ") {
		udec, err := base64.StdEncoding.DecodeString(value[8:])
		if err != nil {
			value = "* invalid value *"
		} else {
			value = string(udec)
		}
	}
	return value
}

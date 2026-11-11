// Package ui встраивает собранный фронтенд в единый бинарный файл.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed static
var content embed.FS

func FS() fs.FS {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

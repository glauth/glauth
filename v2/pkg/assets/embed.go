package assets

import "embed"

// Content is the embedded assets.
//
//go:embed *.tgz js/* css/* *.html
var Content embed.FS

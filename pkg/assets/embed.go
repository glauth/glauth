package assets

import "embed"

// Content is the embedded assets.
//go:embed *.tgz glauth.* *.html
var Content embed.FS

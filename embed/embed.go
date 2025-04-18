package embed

import (
	"embed"
	"errors"
	"io/fs"
	"os"
)

//go:embed assets
var assetsFs embed.FS

//go:embed challenge
var challengeFs embed.FS

//go:embed templates
var templatesFs embed.FS

type FSInterface interface {
	fs.FS
	fs.ReadDirFS
	fs.ReadFileFS
}

func trimPrefix(embedFS embed.FS, prefix string) FSInterface {
	subFS, err := fs.Sub(embedFS, prefix)
	if err != nil {
		panic(err)
	}
	if properFS, ok := subFS.(FSInterface); ok {
		return properFS
	} else {
		panic("unsupported")
	}
}

var ChallengeFs = trimPrefix(challengeFs, "challenge")

var TemplatesFs = trimPrefix(templatesFs, "templates")
var AssetsFs = trimPrefix(assetsFs, "assets")

func GetFallbackFS(embedFS FSInterface, prefix string) (FSInterface, error) {
	var outFs fs.FS
	if stat, err := os.Stat(prefix); err == nil && stat.IsDir() {
		outFs = embedFS
	} else if _, err := embedFS.ReadDir(prefix); err == nil {
		outFs, err = fs.Sub(embedFS, prefix)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	if properFS, ok := outFs.(FSInterface); ok {
		return properFS, nil
	} else {
		return nil, errors.New("unsupported FS")
	}
}

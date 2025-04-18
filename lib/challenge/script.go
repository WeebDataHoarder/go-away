package challenge

import (
	_ "embed"
	"encoding/json"
	"git.gammaspectra.live/git/go-away/utils"
	"net/http"
	"text/template"
)

//go:embed script.mjs
var scriptData []byte

var scriptTemplate = template.Must(template.New("script.mjs").Parse(string(scriptData)))

func ServeChallengeScript(w http.ResponseWriter, r *http.Request, reg *Registration, params any, script string) {
	data := RequestDataFromContext(r.Context())
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")

	paramData, err := json.Marshal(params)
	if err != nil {
		//TODO: log
		panic(err)
	}

	w.WriteHeader(http.StatusOK)

	err = scriptTemplate.Execute(w, map[string]any{
		"Id":              data.Id.String(),
		"Path":            reg.Path,
		"Parameters":      paramData,
		"Random":          utils.CacheBust(),
		"Challenge":       reg.Name,
		"ChallengeScript": script,
	})
	if err != nil {
		//TODO: log
		panic(err)
	}
}

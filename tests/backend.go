package tests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
)

func MakeTestBackend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		responseCode := http.StatusOK
		var err error
		if opt := q.Get("http-code"); opt != "" {
			rc, err := strconv.ParseInt(opt, 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			responseCode = int(rc)
		}
		type ResponseJson struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Query  string `json:"query"`
		}

		if opt := q.Get("mime-type"); opt != "" {
			w.Header().Set("Content-Type", opt)
		} else {
			w.Header().Set("Content-Type", "application/json")
		}

		var data []byte
		if opt := q.Get("content"); opt != "" {
			data, err = base64.RawURLEncoding.DecodeString(opt)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {
			data, err = json.Marshal(ResponseJson{
				Method: r.Method,
				Path:   r.URL.Path,
				Query:  r.URL.RawQuery,
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(responseCode)
		_, _ = w.Write(data)
	})
}

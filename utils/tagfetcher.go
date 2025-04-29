package utils

import (
	"golang.org/x/net/html"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
)

func FetchTags(backend http.Handler, uri *url.URL, kind string) (result []html.Node) {
	writer := httptest.NewRecorder()
	backend.ServeHTTP(writer, &http.Request{
		Method: http.MethodGet,
		URL:    uri,
		Header: http.Header{
			"User-Agent": []string{"Mozilla 5.0 (compatible; go-away/1.0 fetch-tags) TwitterBot/1.0"},
			"Accept":     []string{"text/html,application/xhtml+xml"},
		},
		Close: true,
	})
	response := writer.Result()
	if response == nil {
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil
	}

	if contentType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type")); contentType != "text/html" && contentType != "application/xhtml+xml" {
		return nil
	}

	return FetchTagsFromReader(response.Body, kind)
}

func FetchTagsFromReader(r io.Reader, kind string) (result []html.Node) {
	//TODO: handle non UTF-8 documents
	node, err := html.ParseWithOptions(r, html.ParseOptionEnableScripting(false))
	if err != nil {
		return nil
	}

	for n := range node.Descendants() {
		if n.Type == html.ElementNode && n.Data == kind {
			result = append(result, html.Node{
				Type:      n.Type,
				DataAtom:  n.DataAtom,
				Data:      n.Data,
				Namespace: n.Namespace,
				Attr:      n.Attr,
			})
		}
	}

	return result
}

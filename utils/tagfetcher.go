package utils

import (
	"golang.org/x/net/html"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
)

func FetchTags(backend http.Handler, uri *url.URL, kinds ...string) (result []html.Node) {
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

	//TODO: handle non UTF-8 documents
	node, err := html.ParseWithOptions(response.Body, html.ParseOptionEnableScripting(false))
	if err != nil {
		return nil
	}

	descendants(node, func(n *html.Node) {
		if n.Type == html.ElementNode && slices.Contains(kinds, n.Data) {
			result = append(result, html.Node{
				Type:      n.Type,
				DataAtom:  n.DataAtom,
				Data:      n.Data,
				Namespace: n.Namespace,
				Attr:      n.Attr,
			})
		}
	})

	return result
}

func descendants(n *html.Node, f func(n *html.Node)) {
	f(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		descendants(c, f)
	}
}

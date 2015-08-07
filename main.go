package main

import (
	"fmt"
	"net/http"

	"github.com/codegangsta/negroni"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "---")
	})

	n := negroni.Classic()
	n.UseHandler(mux)
	n.Run(":3000")
}

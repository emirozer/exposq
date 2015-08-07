package main

import (
	"fmt"
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/emirozer/exposq/osquery"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		coq := osquery.CentOsQueries()
		fmt.Println(coq)
		fmt.Fprintf(w, "---")
	})

	n := negroni.Classic()
	n.UseHandler(mux)
	n.Run(":3000")
}

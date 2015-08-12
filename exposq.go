package main

import (
	"net/http"

	"./sshttp"
	"github.com/emirozer/exposq/Godeps/_workspace/src/github.com/codegangsta/negroni"
)

func main() {
	mux := http.NewServeMux()
	// handlers are set seperately
	sshttp.SetMux(*mux)

	n := negroni.Classic()
	n.UseHandler(mux)
	n.Run(":3000")
}

package main

import (
	"net/http"

	"github.com/emirozer/exposq/Godeps/_workspace/src/github.com/codegangsta/negroni"
	"github.com/emirozer/exposq/sshttp"
)

func main() {
	mux := http.NewServeMux()
	// handlers are set seperately
	sshttp.SetMux(*mux)

	n := negroni.Classic()
	n.UseHandler(mux)
	n.Run(":3000")
}

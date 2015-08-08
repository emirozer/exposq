package main

import (
	"net/http"

	"github.com/codegangsta/negroni"
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

package main

import (
	"flag"
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

	vagrant := flag.Bool("vagrant", false, "If you pass the arg -vagrant the http server starts at 0.0.0.0:3000 so portforwarding works")
	flag.Parse()

	if *vagrant {
		n.Run("0.0.0.0:3000")
	} else {
		n.Run(":3000")
	}

}

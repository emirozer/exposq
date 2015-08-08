package sshttp

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"

	"github.com/emirozer/exposq/osquery"
)

// gets http.NewServeMux from main and sets the routes
func SetMux(mux http.ServeMux) {

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		coq := osquery.CentOsQueries()
		fmt.Println(coq)
		fmt.Fprintf(w, "---")
	})

	mux.HandleFunc("/kernel_info", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["kernel_info"] + "\""

		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			log.Println(err)
		}
		sout := string(out[:])

		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/kernel_integrity", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["kernel_integrity"] + "\""

		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			log.Println(err)
		}
		sout := string(out[:])

		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/kernel_modules", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["kernel_modules"] + "\""

		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			log.Println(err)
		}
		sout := string(out[:])

		fmt.Fprintf(w, sout)
	})

}

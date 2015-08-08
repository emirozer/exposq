package sshttp

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/emirozer/exposq/osquery"
)

// Gets http.NewServeMux from main and sets the routes
func SetMux(mux http.ServeMux) {

	oq := osquery.GenericOsQueries()
	coq := osquery.CentOsQueries()
	doq := osquery.DebUbOsQueries()

	const page = `<!DOCTYPE html>
<html>
  <head>
<title>exposq</title>
	<style>
	body {background-color:black}
	p {color:white;
	font-family:courier;
	}
	</style>
  </head>
  <body>
    <p>{{.}}</p>
  </body>
</html>`

	t := template.Must(template.New("page").Parse(page))

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		text := ``
		text += fmt.Sprintf("Generic Os Query Routes:\n\n")
		for k, _ := range oq {
			text += fmt.Sprintf("/" + k + "\n")
		}
		text += fmt.Sprintf("\nRedHat Based Os Query Routes:\n\n")
		for k, _ := range coq {
			text += fmt.Sprintf("/" + k + "\n")
		}
		text += fmt.Sprintf("\nDebian Based Os Query Routes:\n\n")
		for k, _ := range doq {
			text += fmt.Sprintf("/" + k + "\n")
		}
		safe := template.HTMLEscapeString(text)
		fixed := strings.Replace(safe, "\n", "\n<br/>", -1)

		t.Execute(w, template.HTML(fixed))

	})

	mux.HandleFunc("/kernel_info", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["kernel_info"] + "\""
		sout := MainSshHandler(cmd)

		fmt.Fprintf(w, sout)

	})

	mux.HandleFunc("/kernel_integrity", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["kernel_integrity"] + "\""
		sout := MainSshHandler(cmd)

		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/kernel_modules", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["kernel_modules"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/mounts", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["mounts"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/mounts_device_alias_none", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["mounts_device_alias_none"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/block_devices", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["block_devices"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/block_device_sz0", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["block_device_sz0"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/block_device_ata", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["block_device_ata"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/acpi_tables", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["acpi_tables"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/cpuid", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["cpuid"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/crontab", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["crontab"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/disk_encryption", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["disk_encryption"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/etc_hosts", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["etc_hosts"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/etc_protocols", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["etc_protocols"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/etc_services", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["etc_services"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/groups", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["groups"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/interface_addresses", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["interface_addresses"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/interface_details", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["interface_details"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/iptables", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["iptables"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/last", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["last"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/listening_ports", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["listening_ports"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/logged_in_users", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["logged_in_users"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/memory_map", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["memory_map"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/pci_devices", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["pci_devices"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/passwd_changes", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["passwd_changes"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/processes", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["processes"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/processes_root", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["processes_root"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_envs", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["process_envs"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_memory_map", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["process_memory_map"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_open_files", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["process_open_files"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_open_sockets", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["process_open_sockets"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/routes", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["routes"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/shared_memory", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["shared_memory"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/shell_history", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["shell_history"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/users", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["users"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/user_groups", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["user_groups"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/uptime", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["uptime"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/relay", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["relay"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/mitm", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["mitm"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/setuid_enabled", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["setuid_enabled"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/q_scan_ps_bin", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["q_scan_ps_bin"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/ps_lst_tcp_udp", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + oq["ps_lst_tcp_udp"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/rpm_package_files", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + coq["rpm_package_files"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/rpm_packages", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + coq["rpm_packages"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/apt_sources", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + doq["apt_sources"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/deb_packages", func(w http.ResponseWriter, req *http.Request) {

		cmd := "osqueryi " + "\"" + doq["deb_packages"] + "\""
		sout := MainSshHandler(cmd)
		fmt.Fprintf(w, sout)
	})

}

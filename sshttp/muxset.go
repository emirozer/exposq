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
		fmt.Fprintf(w, "Main")
	})

	mux.HandleFunc("/kernel_info", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["kernel_info"] + "\""
		sout := dispatchCmd(cmd)

		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/kernel_integrity", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["kernel_integrity"] + "\""
		sout := dispatchCmd(cmd)

		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/kernel_modules", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["kernel_modules"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/mounts", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["mounts"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/mounts_device_alias_none", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["mounts_device_alias_none"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/block_devices", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["block_devices"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/block_device_sz0", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["block_device_sz0"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/block_device_ata", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["block_device_ata"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/acpi_tables", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["acpi_tables"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/cpuid", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["cpuid"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/crontab", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["crontab"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/disk_encryption", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["disk_encryption"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/etc_hosts", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["etc_hosts"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/etc_protocols", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["etc_protocols"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/etc_services", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["etc_services"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/groups", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["groups"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/interface_addresses", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["interface_addresses"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/interface_details", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["interface_details"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/iptables", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["iptables"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/last", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["last"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/listening_ports", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["listening_ports"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/logged_in_users", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["logged_in_users"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/memory_map", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["memory_map"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/pci_devices", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["pci_devices"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/passwd_changes", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["passwd_changes"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/processes", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["processes"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/processes_root", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["processes_root"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_envs", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["process_envs"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_memory_map", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["process_memory_map"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_open_files", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["process_open_files"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/process_open_sockets", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["process_open_sockets"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/routes", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["routes"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/shared_memory", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["shared_memory"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/shell_history", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["shell_history"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/users", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["users"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/user_groups", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["user_groups"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

	mux.HandleFunc("/uptime", func(w http.ResponseWriter, req *http.Request) {
		oq := osquery.GenericOsQueries()

		cmd := "osqueryi " + "\"" + oq["uptime"] + "\""
		sout := dispatchCmd(cmd)
		fmt.Fprintf(w, sout)
	})

}

func dispatchCmd(cmd string) string {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		log.Println(err)
	}
	sout := string(out[:])

	if len(sout) == 0 {
		sout = fmt.Sprintf("No response for the following query from this machine : %v", cmd)
	}
	return sout
}

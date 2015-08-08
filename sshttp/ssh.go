package sshttp

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/hypersleep/easyssh"
)

//Reads the target file, returns a slice of string slices containing user/ip
//E.g. :[[ec2-user 52.18.229.188] [centos  52.17.136.207]]
func readTarget() {

	target_list := make([][]string, 0)
	t, err := ioutil.ReadFile("../target")
	if err != nil {
		panic(err)
	}
	at := string(t)
	te := strings.Fields(at)
	for _, i := range te {

		target_list = append(target_list, strings.Split(i, "@"))

	}

}

func sshStuff() {
	ssh := &easyssh.MakeConfig{
		User:   "john",
		Server: "example.com",
		// Optional key or Password without either we try to contact your agent SOCKET
		Key:  "~/.ssh/id_rsa",
		Port: "22",
	}

	// Call Run method with command you want to run on remote server.
	response, err := ssh.Run("ps ax")
	// Handle errors
	if err != nil {
		panic("Can't run remote command: " + err.Error())
	} else {
		fmt.Println(response)
	}

}

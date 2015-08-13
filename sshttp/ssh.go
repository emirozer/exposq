package sshttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/emirozer/exposq/Godeps/_workspace/src/golang.org/x/crypto/ssh"
)

type jsonOptions struct {
	Key     string    `json:"key"`
	Targets []*target `json:"targets"`
}

type target struct {
	User string `json:"user"`
	IP   string `json:"ip"`
	Key  string `json:"key"`
}

// func responsible of parsing the target.json file
func readTarget() []*target {
	byt, err := ioutil.ReadFile("targets.json")
	if err != nil {
		panic(err)
	}

	var opts jsonOptions
	err = json.Unmarshal(byt, &opts)

	if err != nil {
		panic(err)
	}

	// set key to default if needed
	for _, t := range opts.Targets {
		if len(t.Key) == 0 {
			t.Key = opts.Key
		}
	}

	return opts.Targets
}

// func that is responsible of setting the session and communicating
func sshDispatch(cmd string, user string, ip string, key string, messages chan<- string) {
	var res string
	pemBytes, err := ioutil.ReadFile(key)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatalf("parse key failed:%v", err)
	}
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}
	conn, err := ssh.Dial("tcp", ip+":22", config)
	if err != nil {
		log.Fatalf("dial failed:%v", err)
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		log.Fatalf("session failed:%v", err)
	}
	defer session.Close()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	err = session.Run(cmd)
	if err != nil {
		// upon dispatching a query that can result in Process exited with 1
		// it shouldn't completly fail, the thing here is that that OS
		// was not compatible with that query, so we handle some cases here

		res += fmt.Sprintf("\nMachine: %v@%v\n", user, ip)

		if strings.Contains(cmd, "apt_resources") || strings.Contains(cmd, "deb_packages") {
			res += fmt.Sprintf("Target is RPM based, query won't return anything: %v\n", cmd)
		} else if strings.Contains(cmd, "rpm_package_files") || strings.Contains(cmd, "rpm_packages") {
			res += fmt.Sprintf("Target is APT based, query won't return anything: %v\n", cmd)
		} else {
			res += fmt.Sprintf("No response for the following query from this machine : %v\n", cmd)
		}

		messages <- res

	} else {

		res += fmt.Sprintf("\nMachine: %v@%v\n", user, ip)
		res += stdoutBuf.String()
		res = string(res[:])
		messages <- res

	}
}

//MainSSHHandler returns the result that has been gathered from target machines
func MainSSHHandler(cmd string) string {
	var sout string
	var soutL []string

	targets := readTarget()
	messages := make(chan string, len(targets))

	for _, t := range targets {
		go sshDispatch(cmd, t.User, t.IP, t.Key, messages)
	}

	for len(soutL) < len(targets) {

		select {
		case <-time.After(time.Second * 20):
			break
		default:
			soutL = append(soutL, <-messages)
		}
	}

	for _, v := range soutL {
		sout += v
	}

	return sout
}

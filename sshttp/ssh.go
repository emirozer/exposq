package sshttp

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	json "github.com/emirozer/exposq/Godeps/_workspace/src/github.com/bitly/go-simplejson"

	"github.com/emirozer/exposq/Godeps/_workspace/src/golang.org/x/crypto/ssh"
)

// func responsible of parsing the target.json file
func readTarget() ([][]string, string) {

	target_list := make([][]string, 0)
	t, err := os.Open("target.json")
	defer t.Close()
	if err != nil {
		panic(err)
	}

	js, err := json.NewFromReader(t)
	if err != nil {
		log.Fatal(err)
	}
	key, _ := js.Get("key").String()

	targets := js.Get("targets")
	temp_t, _ := js.Get("targets").Array()

	for k, _ := range temp_t {
		temp_slice := make([]string, 0)
		user, _ := targets.GetIndex(k).Get("user").String()
		ip, _ := targets.GetIndex(k).Get("ip").String()

		temp_slice = append(temp_slice, user)
		temp_slice = append(temp_slice, ip)
		target_list = append(target_list, temp_slice)
	}

	return target_list, key
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

// Returns the result that has been gathered from target machines
func MainSshHandler(cmd string) string {
	var target_list [][]string
	var key string
	var user string
	var ip string
	var sout string
	var sout_l []string

	target_list, key = readTarget()

	messages := make(chan string, len(target_list))

	for _, j := range target_list {

		user = j[0]
		ip = j[1]

		go sshDispatch(cmd, user, ip, key, messages)

	}

	for len(sout_l) < len(target_list) {

		select {
		case <-time.After(time.Second * 20):
			break
		default:
			sout_l = append(sout_l, <-messages)
		}
	}

	for _, v := range sout_l {
		sout += v
	}

	return sout
}

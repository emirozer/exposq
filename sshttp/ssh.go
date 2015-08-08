package sshttp

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	json "github.com/bitly/go-simplejson"
	"golang.org/x/crypto/ssh"
)

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

func sshDispatch(cmd string, user string, ip string, key string) string {
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
		log.Fatalf("Run failed:%v", err)
	}

	res = stdoutBuf.String()
	return res
}

func MainSshHandler(cmd string) string {
	var target_list [][]string
	var key string
	var user string
	var ip string
	var sout string
	target_list, key = readTarget()

	for _, j := range target_list {

		user = j[0]
		ip = j[1]

		out := sshDispatch(cmd, user, ip, key)
		sout += string(out[:])
	}

	if len(sout) == 0 && (strings.Contains(cmd, "apt_resources") || strings.Contains(cmd, "deb_packages")) {
		sout = fmt.Sprintf("Target is RPM based, query won't return anything: %v", cmd)
	} else if len(sout) == 0 && (strings.Contains(cmd, "rpm_package_files") || strings.Contains(cmd, "rpm_packages")) {
		sout = fmt.Sprintf("Target is APT based, query won't return anything: %v", cmd)
	} else if len(sout) == 0 {
		sout = fmt.Sprintf("No response for the following query from this machine : %v", cmd)
	}

	return sout
}

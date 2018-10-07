package easyssh

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kevinburke/ssh_config"
)

// SSHClient ssh client obj
type SSHClient struct {
	Pre, Next *SSHClient
	Config    *SSHConfig
	Client    *ssh.Client
}

// SSHConfig ssh config
type SSHConfig struct {
	Host, HostName, Password, AliveInterval, ProxyHost, Port, User, Key, KeyPath string
	Timeout                                                                      time.Duration
}

// Stream returns one channel that combines the stdout and stderr of the command
// as it is run on the remote machine, and another that sends true when the
// command is done. The sessions and channels will then be closed.
func (sc *SSHClient) Stream(command string, timeout time.Duration) (<-chan string, <-chan string, <-chan bool, <-chan error, error) {
	// continuously send the command's output over the channel
	stdoutChan := make(chan string)
	stderrChan := make(chan string)
	doneChan := make(chan bool)
	errChan := make(chan error)

	// connect to remote host
	session, err := sc.Connect()
	if err != nil {
		return stdoutChan, stderrChan, doneChan, errChan, err
	}
	defer session.Close()
	// connect to both outputs (they are of type io.Reader)
	outReader, err := session.StdoutPipe()
	if err != nil {
		return stdoutChan, stderrChan, doneChan, errChan, err
	}
	errReader, err := session.StderrPipe()
	if err != nil {
		return stdoutChan, stderrChan, doneChan, errChan, err
	}
	err = session.Start(command)
	if err != nil {
		return stdoutChan, stderrChan, doneChan, errChan, err
	}

	// combine outputs, create a line-by-line scanner
	stdoutReader := io.MultiReader(outReader)
	stderrReader := io.MultiReader(errReader)
	stdoutScanner := bufio.NewScanner(stdoutReader)
	stderrScanner := bufio.NewScanner(stderrReader)

	go func(stdoutScanner, stderrScanner *bufio.Scanner, stdoutChan, stderrChan chan string, doneChan chan bool, errChan chan error) {
		defer close(stdoutChan)
		defer close(stderrChan)
		defer close(doneChan)
		defer close(errChan)
		defer session.Close()

		timeoutChan := time.After(timeout * time.Second)
		res := make(chan struct{}, 1)
		var resWg sync.WaitGroup
		resWg.Add(2)

		go func() {
			for stdoutScanner.Scan() {
				stdoutChan <- stdoutScanner.Text()
			}
			resWg.Done()
		}()

		go func() {
			for stderrScanner.Scan() {
				stderrChan <- stderrScanner.Text()
			}
			resWg.Done()
		}()

		go func() {
			resWg.Wait()
			// close all of our open resources
			res <- struct{}{}
		}()

		select {
		case <-res:
			errChan <- session.Wait()
			doneChan <- true
		case <-timeoutChan:
			stderrChan <- "Run Command Timeout!"
			errChan <- nil
			doneChan <- false
		}
	}(stdoutScanner, stderrScanner, stdoutChan, stderrChan, doneChan, errChan)

	return stdoutChan, stderrChan, doneChan, errChan, err
}

// Run command on remote machine and returns its stdout as a string
func (sc *SSHClient) Run(command string, timeout time.Duration) (outStr string, errStr string, isTimeout bool, err error) {
	stdoutChan, stderrChan, doneChan, errChan, err := sc.Stream(command, timeout)
	if err != nil {
		return outStr, errStr, isTimeout, err
	}
	// read from the output channel until the done signal is passed
loop:
	for {
		select {
		case isTimeout = <-doneChan:
			break loop
		case outline := <-stdoutChan:
			if outline != "" {
				outStr += outline + "\n"
			}
		case errline := <-stderrChan:
			if errline != "" {
				errStr += errline + "\n"
			}
		case err = <-errChan:
		}
	}
	// return the concatenation of all signals from the output channel
	return outStr, errStr, isTimeout, err
}

// Scp uploads sourceFile to remote machine like native scp console app.
func (sc *SSHClient) Scp(sourceFile string, etargetFile string) error {
	session, err := sc.Connect()

	if err != nil {
		return err
	}
	defer session.Close()

	targetFile := filepath.Base(etargetFile)

	src, srcErr := os.Open(sourceFile)

	if srcErr != nil {
		return srcErr
	}

	srcStat, statErr := src.Stat()

	if statErr != nil {
		return statErr
	}

	go func() {
		w, err := session.StdinPipe()

		if err != nil {
			return
		}
		defer w.Close()

		fmt.Fprintln(w, "C0644", srcStat.Size(), targetFile)

		if srcStat.Size() > 0 {
			io.Copy(w, src)
			fmt.Fprint(w, "\x00")
		} else {
			fmt.Fprint(w, "\x00")
		}
	}()

	return session.Run(fmt.Sprintf("scp -tr %s", etargetFile))
}

// 最后格式化一个ssh config
func (sc *SSHClient) getSSHConfig() *ssh.ClientConfig {
	// auths holds the detected ssh auth methods
	auths := []ssh.AuthMethod{}

	// figure out what auths are requested, what is supported
	if sc.Config.Password != "" {
		auths = append(auths, ssh.Password(sc.Config.Password))
	}
	if sc.Config.KeyPath != "" {
		if pubkey, err := getKeyFile(sc.Config.KeyPath); err != nil {
			log.Printf("getKeyFile: %v\n", err)
		} else {
			auths = append(auths, ssh.PublicKeys(pubkey))
		}
	}

	if sc.Config.Key != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(sc.Config.Key)); err != nil {
			log.Printf("ssh.ParsePrivateKey: %v\n", err)
		} else {
			auths = append(auths, ssh.PublicKeys(signer))
		}
	}

	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		defer sshAgent.Close()
	}

	return &ssh.ClientConfig{
		Timeout:         sc.Config.Timeout,
		User:            sc.Config.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

// NewClient new ssh client, return the first client of the chain
func (sc *SSHClient) NewClient() (*ssh.Client, error) {
	var (
		err       error
		client    *ssh.Client
		sshClient = sc.last()
	)

	if sshClient.Client == nil {
		targetConfig := sshClient.getSSHConfig()
		if sshClient.Client, err = ssh.Dial("tcp", net.JoinHostPort(sshClient.Config.HostName, sshClient.Config.Port), targetConfig); err != nil {
			return nil, err
		}

		client = sshClient.Client
	}

	for {
		if sshClient.Pre == nil {
			break
		}
		if client, err = sshClient.proxyClient(); err != nil {
			return nil, err
		}

		sshClient = sshClient.Pre
		sshClient.Client = client
	}

	return client, nil
}

// 获取上一级代理的client
func (sc *SSHClient) proxyClient() (*ssh.Client, error) {
	var (
		err             error
		preConfig       = sc.Pre.Config
		preTargetConfig = sc.Pre.getSSHConfig()
	)
	if sc.Pre == nil {
		return nil, errors.New("pre proxyClient is empty")
	}

	conn, err := sc.Client.Dial("tcp", net.JoinHostPort(preConfig.HostName, preConfig.Port))
	if err != nil {
		return nil, err
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(preConfig.HostName, preConfig.Port), preTargetConfig)
	if err != nil {
		return nil, err
	}

	sc.Pre.Client = ssh.NewClient(ncc, chans, reqs)
	return sc.Pre.Client, nil
}

// Connect to remote server using MakeConfig struct and returns *ssh.Session
func (sc *SSHClient) Connect() (*ssh.Session, error) {
	var client *ssh.Client
	var err error

	if client, err = sc.NewClient(); err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

// get the last of the chain
func (sc *SSHClient) last() *SSHClient {
	sshClient := sc

	for {
		if sshClient.Next != nil {
			sshClient = sshClient.Next
		} else {
			break
		}
	}

	return sshClient
}

// get the first of the chain
func (sc *SSHClient) first() *SSHClient {
	sshClient := sc

	for {
		if sshClient.Pre != nil {
			sshClient = sc.Pre
		} else {
			break
		}
	}

	return sshClient
}

func (sc *SSHClient) nextClient(cfg *ssh_config.Config) *SSHClient {
	if len(sc.Config.ProxyHost) == 0 {
		return nil
	}

	proxyHost := getHostConfig(cfg, sc.Config.ProxyHost)

	proxySSHClient := &SSHClient{
		Config: proxyHost,
	}

	return proxySSHClient
}

// get config file handler
func getConfigFile(configpath string) (*ssh_config.Config, error) {
	var (
		cfgpath string
		err     error
		f       *os.File
	)

	if cfgpath, err = getConfigPath(configpath); err != nil {
		return nil, err
	}
	if f, err = os.Open(cfgpath); err != nil {
		if os.IsExist(err) {
			return nil, nil
		}
		return nil, err
	}

	cfg, _ := ssh_config.Decode(f)
	return cfg, nil
}

// 获取 .ssh config, 并格式化指定host
func getHostConfig(cfg *ssh_config.Config, name string) *SSHConfig {
	var (
		hostName, port, user, keyPath string
	)
	hostName, _ = cfg.Get(name, "HostName")
	port, _ = cfg.Get(name, "Port")
	user, _ = cfg.Get(name, "User")
	keyPath, _ = cfg.Get(name, "IdentityFile")

	sshConfig := &SSHConfig{
		Host:     name,
		HostName: hostName,
		Port:     port,
		User:     user,
		KeyPath:  keyPath,
	}

	proxyCmd, _ := cfg.Get(name, "ProxyCommand")
	proxyArr := strings.Split(proxyCmd, " ")

	if len(proxyArr) > 1 {
		sshConfig.ProxyHost = proxyArr[1]
	}
	return sshConfig
}

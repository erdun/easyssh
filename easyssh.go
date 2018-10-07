package easyssh

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/kevinburke/ssh_config"
)

// MainConfig Contains main authority information.
// User field should be a name of user on remote server (ex. john in ssh john@example.com).
// Server field should be a remote machine address (ex. example.com in ssh john@example.com)
// Key is a path to private key on your local machine.
// Port is SSH server port on remote machine.
// Note: easyssh looking for private key in user's home directory (ex. /home/john + Key).
// Then ensure your Key begins from '/' (ex. /.ssh/id_rsa)
type MainConfig struct {
	Host, User, HostName, Key, KeyPath, Port, Password, ConfigPath string
	Timeout                                                        time.Duration
}

// InitSSHClient init ssh client and return the first one
func (mc *MainConfig) InitSSHClient() (*SSHClient, error) {
	var (
		err                             error
		firstClient, client, nextClient *SSHClient
		config                          *ssh_config.Config
	)

	if config, err = getConfigFile(mc.ConfigPath); err != nil {
		return nil, err
	}
	if mc.Timeout == time.Duration(0) {
		mc.Timeout = time.Duration(60) * time.Second
	}

	sshConfig := &SSHConfig{
		Host:     mc.Host,
		HostName: mc.HostName,
		User:     mc.User,
		Key:      mc.Key,
		KeyPath:  mc.KeyPath,
		Port:     mc.Port,
		Password: mc.Password,
		Timeout:  mc.Timeout,
	}

	firstClient = &SSHClient{
		Config: sshConfig,
	}
	client = firstClient

	if config == nil {
		return firstClient, nil
	}

	hostConfig := getHostConfig(config, mc.Host)
	if len(sshConfig.Host) == 0 {
		sshConfig.Host = hostConfig.Host
	}
	if len(sshConfig.HostName) == 0 {
		sshConfig.HostName = hostConfig.HostName
	}
	if len(sshConfig.Password) == 0 {
		sshConfig.Password = hostConfig.Password
	}
	if len(sshConfig.ProxyHost) == 0 {
		sshConfig.ProxyHost = hostConfig.ProxyHost
	}
	if len(sshConfig.Port) == 0 {
		sshConfig.Port = hostConfig.Port
	}
	if len(sshConfig.User) == 0 {
		sshConfig.User = hostConfig.User
	}
	if len(sshConfig.Key) == 0 {
		sshConfig.Key = hostConfig.Key
	}
	if len(sshConfig.KeyPath) == 0 {
		sshConfig.KeyPath = hostConfig.KeyPath
	}

	for {
		nextClient = client.nextClient(config)

		if nextClient == nil {
			break
		}

		client.Next = nextClient
		nextClient.Pre = client

		client = nextClient
	}
	return firstClient, nil
}

// Run run cmd
func Run(host, cmd string) (outStr string, errStr string, isTimeout bool, err error) {
	mainCfg := &MainConfig{
		Host: host,
	}
	client, err := mainCfg.InitSSHClient()

	if err != nil {
		return "", "", false, err
	}

	return client.Run(cmd, 30)
}

// Stream run cmd
func Stream(host, cmd string) (<-chan string, <-chan string, <-chan bool, <-chan error, error) {
	stdoutChan := make(<-chan string)
	stderrChan := make(<-chan string)
	doneChan := make(<-chan bool)
	errChan := make(<-chan error)

	mainCfg := &MainConfig{
		Host: host,
	}
	client, err := mainCfg.InitSSHClient()

	if err != nil {
		return stdoutChan, stderrChan, doneChan, errChan, err
	}

	stdoutChan, stderrChan, doneChan, errChan, err = client.Stream(cmd, 30)
	return stdoutChan, stderrChan, doneChan, errChan, err
}

// SendFile send file to remote server
func SendFile(host, sourceFile, destFile string) error {
	mainCfg := &MainConfig{
		Host: host,
	}
	client, err := mainCfg.InitSSHClient()

	if err != nil {
		return err
	}

	return client.Scp(sourceFile, destFile)
}

// FetchFile fetch file from remote server to local
func FetchFile(host, sourceFile, destFile string) error {
	mainCfg := &MainConfig{
		Host: host,
	}
	client, err := mainCfg.InitSSHClient()
	if err != nil {
		return err
	}

	fl, err := os.OpenFile(destFile, os.O_CREATE|os.O_WRONLY, 0755)
	defer fl.Close()
	if err != nil {
		return err
	}

	if sourceFile == "" {
		return errors.New("source file con't be empty")
	}
	stdoutChan, _, doneChan, errChan, err := client.Stream(fmt.Sprintf("cat %s", sourceFile), 60)
	if err != nil {
		return err
	}

	// read from the output channel until the done signal is passed
loop:
	for {
		select {
		case <-doneChan:
			break loop
		case outline := <-stdoutChan:
			if outline != "" {
				_, err := fl.Write([]byte(outline + "\n"))
				if err != nil {
					return err
				}
			}
		case err = <-errChan:
		}
	}

	return err
}

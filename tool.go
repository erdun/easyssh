package easyssh

import (
	"io/ioutil"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
)

type sshCfg struct {
	ssh_config.Config
}

type sshConfig interface {
	Get(string, string) (string, error)
	String() string
}

// get config path, support ~ path, if not set configpaht
// will use default config path ~/.ssh/config
func getConfigPath(rawpath string) (string, error) {
	var (
		err error
		usr *user.User
	)

	if usr, err = user.Current(); err != nil {
		return "", err
	}
	homepath := usr.HomeDir

	return getPath(rawpath, filepath.Join(homepath, ".ssh", "config"))
}

// get ssh privat key path, default ~/.ssh/id_rsa
func getKeyPath(rawpath string) (string, error) {
	var (
		err error
		usr *user.User
	)

	if usr, err = user.Current(); err != nil {
		return "", err
	}
	homepath := usr.HomeDir

	return getPath(rawpath, filepath.Join(homepath, ".ssh", "id_rsa"))
}

// get path
func getPath(rawpath, defaultPath string) (string, error) {
	var (
		path = rawpath
		err  error
		usr  *user.User
	)

	if usr, err = user.Current(); err != nil {
		return "", err
	}
	homepath := usr.HomeDir

	// if not set configpath use default value
	if len(rawpath) == 0 {
		return defaultPath, nil
	}

	if rawpath == "~" {
		path = homepath
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(homepath, rawpath[2:])
	}

	return path, nil
}

// returns ssh.Signer from user you running app home path + cutted key path.
// (ex. pubkey,err := getKeyFile("/.ssh/id_rsa") )
func getKeyFile(keypath string) (ssh.Signer, error) {
	var (
		err error
	)
	if keypath, err = getKeyPath(keypath); err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadFile(keypath)
	if err != nil {
		return nil, err
	}

	pubkey, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}

	return pubkey, nil
}

package easyssh

import (
	"fmt"
	"testing"
)

func TestMainConfig(t *testing.T) {
	mainCfg := &MainConfig{
		Host: "w2_t_m_nginx_in",
	}
	client, err := mainCfg.InitSSHClient()

	if err != nil {
		println("init client error")
		return
	}

	stdout, stderr, done, err := client.Run("w", 60)
	// Handle errors
	if err != nil {
		panic("Can't run remote command: " + err.Error())
	} else {
		fmt.Println("don is :", done, "stdout is :", stdout, ";   stderr is :", stderr)
	}

	// assert := assert.New(t)

}

func TestScp(t *testing.T) {
	FetchFile("hz_s_pre_node", "/tmp/tmp", "/tmp/fetch")
}

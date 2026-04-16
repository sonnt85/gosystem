package gosystem

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKillProcess(t *testing.T) {
	fmt.Println("parrent pid: ", os.Getppid())
	time.Sleep(time.Second * 29)
	err := KillPid(1716431)
	require.Nil(t, err)
}

//go:build android && go1.26

package libbox

import "os"

func init() {
	_ = os.ErrInvalid
}

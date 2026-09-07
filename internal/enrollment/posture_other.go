//go:build !linux && !windows

package enrollment

import "runtime"

func collectPosture() Posture { return Posture{OSName: runtime.GOOS} }

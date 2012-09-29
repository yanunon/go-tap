package main

import(
	"github.com/yanunon/go-tap/tap"
)

func init() {
	s := tap.NewServer("KEY", "SECRET", "HOST(xxxx.appspot.com)", "https", "DATA_DIR", 0)
	s.ListenAndServe("")
}

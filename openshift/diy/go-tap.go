package main

import (
	"fmt"
	"github.com/yanunon/go-tap/tap"
	"os"
)

func main() {
	data_dir := os.Getenv("OPENSHIFT_DATA_DIR")
	s := tap.NewServer("KEY", "SECRET", "HOST", "https", data_dir, 1)
	ip := os.Getenv("OPENSHIFT_INTERNAL_IP")
	s.ListenAndServe(fmt.Sprintf("%s:8080", ip))
}

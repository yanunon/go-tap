package main

import(
	"github.com/yanunon/go-tap/tap"
	"os"
	"fmt"
)

func main() {
	data_dir := os.Getenv("OPENSHIFT_DATA_DIR")
	s := tap.NewServer("KEY", "SECRET", "your_id.rhcloud.com", "https", data_dir, 1)
	ip := os.Getenv("OPENSHIFT_INTERNAL_IP")
	s.ListenAndServe(fmt.Sprintf("%s:8080", ip))
}

package tap

import(
	"net/http"
	"html/template"
	"appengine"
	"appengine/urlfetch"
	"strings"
	"io"
	"fmt"
	"math/rand"
)

//ServerType:
//Google Appengine = 0
//RedHat Openshift = 1
type Server struct {
	API_KEY string
	API_SECRET string
	Host string
	Scheme string
	DataDir string
	ServerType int
	Templates *template.Template
}

func NewServer(key, secret, host, scheme, dataDir string, serverType int) (*Server) {
	server := &Server{
		API_KEY: key,
		API_SECRET: secret,
		Host: host,
		Scheme: scheme,
		DataDir: dataDir,
		ServerType: serverType,
	}
	//template
	server.Templates = template.Must(template.ParseFiles(
		server.DataDir + "template/index.html",
		server.DataDir + "template/getapi.html",
	))


	return server
}

func (s *Server) ListenAndServe(addr string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {s.IndexHandler(w, r)})
	http.HandleFunc("/i/", func(w http.ResponseWriter, r *http.Request) {s.ImageProxyHandler(w, r)})
}

func (s *Server) IndexHandler(w http.ResponseWriter, r *http.Request) {
	s.Templates.ExecuteTemplate(w, "index.html", nil)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (s *Server) ImageProxyHandler(w http.ResponseWriter, r *http.Request) {
	client := s.getHttpClient(r)

	url_parts := strings.Split(r.URL.Path, "/")
	img_url := strings.Join(url_parts[2:], "/")
	twimg_url := ""
	if url_parts[2] == "media" {
		twimg_url = fmt.Sprintf("http://pbs.twimg.com/%s", img_url)
	}else {
		twimg_url = fmt.Sprintf("http://a%d.twimg.com/%s", rand.Int()%4, img_url)
	}
	
	resp, err := client.Get(twimg_url)
	if err != nil {
		w.WriteHeader(404)
		fmt.Fprintln(w, twimg_url)
		fmt.Println(err)
		return
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if resp.Body != nil {
		io.Copy(w, resp.Body)
	}
}

func (s *Server) getHttpClient(r *http.Request) (client *http.Client){
	switch s.ServerType {
	case 0:
		c := appengine.NewContext(r)
		client = urlfetch.Client(c)
	case 1:
		client = http.DefaultClient
	}
	return
}

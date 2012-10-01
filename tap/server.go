package tap

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/garyburd/go-oauth/oauth"
	"html/template"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	NoAuthError         = errors.New("No Authorization Data")
	NotBasicAuthError   = errors.New("Not Basic Authorization")
	NotMatchPasswdError = errors.New("Not Match Password")
	NotExistUserError   = errors.New("Not Exist User")

	expand_tco_xml_re         = regexp.MustCompile("<url>([\\w\\.:/]+?)</url>\\s+?<display_url>[\\w\\.:/]+?</display_url>\\s+?<expanded_url>([\\w\\.:/]+?)</expanded_url>")
	expand_tco_json_re        = regexp.MustCompile("\"url\":\"([^\"]+?)\",[^{}]*?\"expanded_url\":\"([^\"]+?)\"")
	parse_profile_img_json_re = regexp.MustCompile("\"(https?:\\\\/\\\\/[\\w]+?\\.twimg\\.com)([^\"]+?)\"")
	parse_profile_img_xml_re  = regexp.MustCompile(">(https?://[\\w]+?\\.twimg\\.com)([^<]+?)<")

	valid_str_re          = regexp.MustCompile("[^a-zA-Z0-9]")
	oauth_token_re        = regexp.MustCompile("oauth_token=([0-9a-zA-Z]+)")
	authenticity_token_re = regexp.MustCompile("authenticity_token = '([0-9a-zA-Z]+)'")
	happy_callback_re     = regexp.MustCompile("\"(http.+?oauth_token.+?oauth_verifier[^\"]+)\"")
)

const unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"

//ServerType:
//Google Appengine = 0
//RedHat Openshift = 1
type Server struct {
	Host        string
	Scheme      string
	DataDir     string
	ServerType  int
	Templates   *template.Template
	UserData    map[string]UserData
	OAuthClient *oauth.Client
}

type UserData struct {
	ScreenName       string
	OAuthTokenSecret string
	OAuthToken       string
	Password         string
	UserId           string
}

func NewServer(key, secret, host, scheme, dataDir string, serverType int) *Server {
	server := &Server{
		Host:       host,
		Scheme:     scheme,
		DataDir:    dataDir,
		ServerType: serverType,
	}
	//template
	server.Templates = template.Must(template.ParseFiles(
		server.DataDir+"template/index.html",
		server.DataDir+"template/oauth.html",
	))

	//oauth
	credentials := oauth.Credentials{
		Token:  key,
		Secret: secret,
	}
	server.OAuthClient = &oauth.Client{
		TemporaryCredentialRequestURI: "https://api.twitter.com/oauth/request_token",
		ResourceOwnerAuthorizationURI: "https://api.twitter.com/oauth/authenticate",
		TokenRequestURI:               "https://api.twitter.com/oauth/access_token",
		Credentials:                   credentials,
	}
	server.UserData = map[string]UserData{}

	return server
}

func (s *Server) ListenAndServe(addr string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { s.IndexHandler(w, r) })
	http.HandleFunc("/i/", func(w http.ResponseWriter, r *http.Request) { s.ImageProxyHandler(w, r) })
	http.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) { s.AuthHandler(w, r) })
	http.HandleFunc("/o/", func(w http.ResponseWriter, r *http.Request) { s.OverrideHandler(w, r) })
	switch s.ServerType {
	case 0:
	case 1:
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(s.DataDir+"static"))))
		http.ListenAndServe(addr, nil)
	}
}

type IndexTemParams struct {
	OAuthType bool
}

func (s *Server) IndexHandler(w http.ResponseWriter, r *http.Request) {
	indexParams := IndexTemParams{true}
	getType := r.FormValue("auth")
	if getType == "basic" {
		indexParams.OAuthType = false
	}
	s.Templates.ExecuteTemplate(w, "index.html", indexParams)
}

func (s *Server) ImageProxyHandler(w http.ResponseWriter, r *http.Request) {
	httpClient := s.getHttpClient(r)

	url_parts := strings.Split(r.URL.Path, "/")
	img_url := strings.Join(url_parts[2:], "/")
	twimg_url := ""
	if url_parts[2] == "media" {
		twimg_url = fmt.Sprintf("http://pbs.twimg.com/%s", img_url)
	} else {
		twimg_url = fmt.Sprintf("http://a%d.twimg.com/%s", rand.Int()%4, img_url)
	}

	resp, err := httpClient.Get(twimg_url)
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

func (s *Server) getBasicAuth(r *http.Request) (u UserData, err error) {
	auth_str := r.Header.Get("Authorization")
	if auth_str == "" {
		err = NoAuthError
		return
	}
	auths := strings.Split(auth_str, " ")
	if strings.ToLower(auths[0]) != "basic" {
		err = NotBasicAuthError
		return
	}
	auths_bytes, err := base64.StdEncoding.DecodeString(auths[1])
	if err != nil {
		err = NotBasicAuthError
		return
	}
	user_pass := strings.Split(string(auths_bytes), ":")
	user := user_pass[0]
	passwd := user_pass[1]

	u, err = s.getUserData(user, r)
	if err != nil {
		return
	}

	if passwd != u.Password {
		fmt.Printf("passwd:%s uPassword:%s\n", passwd, u.Password)
		err = NotMatchPasswdError
		return
	}
	return
}

type OAuthTemplateParam struct {
	GetType1 bool
	BaseUrl  string
}

func (s *Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	httpClient := s.getHttpClient(r)
	session, _ := Session.Get(r, "go-twip")
	baseUrl := s.Scheme + "://" + s.Host

	if r.Method == "POST" {
		auth_type := r.FormValue("auth")
		gt_passwd := r.FormValue("gt_password")
		//gt_passwd = valid_str_re.ReplaceAllString(url_suffix, "")
		session.Values["gt_passwd"] = gt_passwd
		session.Save(r, w)
		callback_url := baseUrl + "/auth/"
		tempCred, err := s.OAuthClient.RequestTemporaryCredentials(httpClient, callback_url, nil)

		if err == nil {
			session.Values["oauth_token"] = tempCred.Token
			session.Values["oauth_token_secret"] = tempCred.Secret
			session.Save(r, w)
			oauthUrl := s.OAuthClient.AuthorizationURL(tempCred, nil)
			if auth_type == "oauth" {
				http.Redirect(w, r, oauthUrl, 302)
			} else {
				id := r.FormValue("username")
				passwd := r.FormValue("password")
				happy_callback_url, err := OAuthProxy(httpClient, id, passwd, oauthUrl)
				if err == nil {
					http.Redirect(w, r, happy_callback_url, 302)
				} else {
					fmt.Fprint(w, err)
					return
				}
			}
		} else {
			fmt.Fprint(w, err)
			return
		}
	} else if r.Method == "GET" {
		if r.FormValue("oauth_token") != "" && r.FormValue("oauth_verifier") != "" {
			tempCred := oauth.Credentials{
				//Token: session.Values["oauth_token"].(string),
				Token: r.FormValue("oauth_token"),
			}
			cred, vars, err := s.OAuthClient.RequestToken(httpClient, &tempCred, r.FormValue("oauth_verifier"))
			if err == nil {
				gt_passwd := session.Values["gt_passwd"].(string)
				screen_name := vars["screen_name"][0]
				userData := UserData{
					ScreenName:       screen_name,
					OAuthToken:       cred.Token,
					OAuthTokenSecret: cred.Secret,
					UserId:           vars["user_id"][0],
					Password:         gt_passwd,
				}
				//c.Infof("%+v\n", vars)
				err := s.setUserData(userData, r)
				if err == nil {
					s.Templates.ExecuteTemplate(w, "oauth.html", baseUrl)
					return
				} else {
					fmt.Fprintln(w, err)
				}

			} else {
				fmt.Fprintln(w, err)
			}

			return
		}
	}
}

func OAuthProxy(httpClient *http.Client, id string, passwd string, oauthUrl string) (happy_callback_url string, err error) {
	resp, err := httpClient.Get(oauthUrl)
	if err != nil {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	body_str := string(body)

	oauth_token := oauth_token_re.FindStringSubmatch(body_str)
	authenticity_token := authenticity_token_re.FindStringSubmatch(body_str)

	post_str := fmt.Sprintf("oauth_token=%s&authenticity_token=%s&session[username_or_email]=%s&session[password]=%s", urlEncode(oauth_token[1]), urlEncode(authenticity_token[1]), urlEncode(id), urlEncode(passwd))

	req, _ := http.NewRequest("POST", "https://api.twitter.com/oauth/authorize", strings.NewReader(post_str))
	cookies := resp.Cookies()
	for i := range cookies {
		req.AddCookie(cookies[i])
	}
	resp, err = httpClient.Do(req)
	if err != nil {
		return
	}

	body, _ = ioutil.ReadAll(resp.Body)
	body_str = string(body)

	happy_callback := happy_callback_re.FindStringSubmatch(body_str)
	if len(happy_callback) == 2 {
		happy_callback_url = happy_callback[1]
	}
	return
}

func (s *Server) OverrideHandler(w http.ResponseWriter, r *http.Request) {
	httpClient := s.getHttpClient(r)
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)
	url_parts := strings.Split(r.URL.Path, "/")

	file_type_idx := strings.LastIndex(r.URL.Path, ".")
	file_type := ""
	if file_type_idx > -1 {
		file_type = r.URL.Path[file_type_idx+1:]
	}

	userData, err := s.getBasicAuth(r)
	if err != nil && err != NoAuthError {
		fmt.Fprintln(w, err)
		return
	}

	forwardHeader := r.Header
	//forwardHeader.Del("Accept-Encoding")
	forwardUrl := strings.Join(url_parts[2:], "/")
	forwardUrl = "https://api.twitter.com/1/" + forwardUrl
	params := make(url.Values)
	//fmt.Println(forwardUrl)
	r.ParseForm()
	if r.Form != nil {
		params = r.Form
	}
	params["include_entities"] = []string{"true"} //force it true
	if params.Get("since_id") == "-1" {
		params.Del("since_id")
	}
	if userData.OAuthToken != "" {
		cred := oauth.Credentials{
			Token:  userData.OAuthToken,
			Secret: userData.OAuthTokenSecret,
		}
		s.OAuthClient.SignParam(&cred, r.Method, forwardUrl, params)
	}
	forwardUrl = forwardUrl + "?" + params.Encode()
	forwardBody := ""
	if r.Body != nil {
		forwardBodys, _ := ioutil.ReadAll(r.Body)
		forwardBody = string(forwardBodys)
	}
	forwardReq, _ := http.NewRequest(r.Method, forwardUrl, strings.NewReader(forwardBody))
	forwardReq.Header = forwardHeader
	//fmt.Printf("HEADER-1:%+v\n", forwardHeader)
	resp, err := httpClient.Do(forwardReq)
	if err != nil {
		return
	}

	copyHeader(w.Header(), resp.Header)
	//rewrite body
	var body []byte
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipR, _ := gzip.NewReader(resp.Body)
		defer resp.Body.Close()
		body, _ = ioutil.ReadAll(gzipR)
		defer gzipR.Close()
	} else {
		body, _ = ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
	}
	body_str := string(body)
	body_str = s.expandTCO(body_str, file_type)
	if r.Header.Get("User-Agent") != "Twigee" {
		body_str = s.parseImageUrl(body_str, file_type, r)
	}
	buffer := new(bytes.Buffer)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipW := gzip.NewWriter(buffer)
		nBody := []byte(body_str)
		gzipW.Write(nBody)
		gzipW.Close()
	} else {
		buffer.WriteString(body_str)
	}
	w.Header().Set("Content-Length", strconv.Itoa(buffer.Len()))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, buffer)
}

func (s *Server) expandTCO(body, file_type string) (body_expanded string) {
	//body_expanded = expand_tco_xml_re.ReplaceAllString(body, "<url>$3</url>$2<expanded_url>$3</expanded_url>")
	body_expanded = body
	var expand_tco_re *regexp.Regexp
	if file_type == "xml" {
		expand_tco_re = expand_tco_xml_re
	} else {
		expand_tco_re = expand_tco_json_re
	}
	find_pair := expand_tco_re.FindAllStringSubmatch(body_expanded, -1)
	for i := range find_pair {
		body_expanded = strings.Replace(body_expanded, find_pair[i][1], find_pair[i][2], -1)
	}
	return
}

func (s *Server) parseImageUrl(body, file_type string, r *http.Request) (body_parsed string) {
	if file_type == "xml" {
		replace_str := fmt.Sprintf(">%s://%s/i$2<", s.Scheme, s.Host)
		body_parsed = parse_profile_img_xml_re.ReplaceAllString(body, replace_str)
	} else {
		replace_str := fmt.Sprintf("\"%s:\\/\\/%s\\/i$2\"", s.Scheme, s.Host)
		body_parsed = parse_profile_img_json_re.ReplaceAllString(body, replace_str)
	}
	return
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func urlEncode(val string) (ret string) {
	for i := 0; i < len(val); i++ {
		c := val[i]
		s := string(c)
		if strings.Index(unreservedChars, s) != -1 {
			ret += s
		} else {
			ret += fmt.Sprintf("%%%s%s", string("0123456789ADCDEF"[c>>4]), string("0123456789ABCDEF"[c&15]))
		}
	}
	return
}

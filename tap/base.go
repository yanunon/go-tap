// +build !appengine

package tap

import (
	"code.google.com/p/gorilla/sessions"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
)

var (
	Session = sessions.NewCookieStore([]byte("go-tap-very-secret"))
)

func (s *Server) getUserData(screen_name string, r *http.Request) (u UserData, err error) {
	u, ok := s.UserData[screen_name]
	if !ok {
		switch s.ServerType {
		case 0:
		case 1:
			bin, err := ioutil.ReadFile(s.DataDir + screen_name + ".json")
			if err == nil {
				err = json.Unmarshal(bin, &u)
			}
		}
	}
	return
}

func (s *Server) setUserData(u UserData, r *http.Request) (err error) {
	s.UserData[u.ScreenName] = u
	switch s.ServerType {
	case 0:
	case 1:
		bin, err := json.Marshal(u)
		if err == nil {
			err = ioutil.WriteFile(s.DataDir+u.ScreenName+".json", bin, os.ModePerm)
		}
	}
	return
}

func (s *Server) getHttpClient(r *http.Request) (client *http.Client) {
	switch s.ServerType {
	case 0:
	case 1:
		client = http.DefaultClient
	}
	return
}

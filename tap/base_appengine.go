// +build appengine

package tap

import (
	"appengine"
	"appengine/datastore"
	"appengine/urlfetch"
	"code.google.com/p/gorilla/appengine/sessions"
	"net/http"
)

var (
	Session = sessions.NewDatastoreStore("", []byte("go-tap-very-secret"))
)

func (s *Server) getUserData(screen_name string, r *http.Request) (u UserData, err error) {
	u, ok := s.UserData[screen_name]
	if !ok {
		switch s.ServerType {
		case 0:
			c := appengine.NewContext(r)
			q := datastore.NewQuery("UserData").Filter("ScreenName =", screen_name)
			t := q.Run(c)
			_, err = t.Next(&u)
		case 1:
		}
	}
	return
}

func (s *Server) setUserData(u UserData, r *http.Request) (err error) {
	s.UserData[u.ScreenName] = u
	switch s.ServerType {
	case 0:
		c := appengine.NewContext(r)
		q := datastore.NewQuery("UserData").Filter("ScreenName =", u.ScreenName)
		for t := q.Run(c); ; {
			var x UserData
			key, err := t.Next(&x)
			if err == datastore.Done {
				break
			}
			datastore.Delete(c, key)
		}
		_, err = datastore.Put(c, datastore.NewIncompleteKey(c, "UserData", nil), &u)
	case 1:
	}
	return
}

func (s *Server) getHttpClient(r *http.Request) (client *http.Client) {
	switch s.ServerType {
	case 0:
		c := appengine.NewContext(r)
		client = urlfetch.Client(c)
	case 1:
	}
	return
}

func (s *Server) ClearData(name string, r *http.Request) (err error) {
	switch s.ServerType {
	case 0:
		c := appengine.NewContext(r)
		keys, err1 := datastore.NewQuery(name).KeysOnly().GetAll(c, nil)
		if err1 != nil {
			return err1
		}
		err = datastore.DeleteMulti(c, keys)
	case 1:
	}
	return
}


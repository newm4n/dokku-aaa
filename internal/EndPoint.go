package internal

import (
	"github.com/gorilla/mux"
	"net/http"
)

func InitRouter(r *mux.Router) {
	aaa := &TheHandler{}
	r.HandleFunc("/login", aaa.Login).Methods(http.MethodPost)
	r.HandleFunc("/refresh", aaa.Refresh).Methods(http.MethodPost)
	r.HandleFunc("/register", aaa.Register).Methods(http.MethodPost)
	r.HandleFunc("/unregister", aaa.UnRegister).Methods(http.MethodPost)
}

type TheHandler struct {
}

func (hdler *TheHandler) Login(response http.ResponseWriter, request *http.Request) {

}

func (hdler *TheHandler) Refresh(response http.ResponseWriter, request *http.Request) {

}

func (hdler *TheHandler) Register(response http.ResponseWriter, request *http.Request) {

}

func (hdler *TheHandler) UnRegister(response http.ResponseWriter, request *http.Request) {

}

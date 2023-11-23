package internal

import (
	"github.com/gorilla/mux"
	"net/http"
)

func InitRouter(r *mux.Router) {
	aaa := &TheHandler{
		DAO: &MemoryDAO{
			UserAccountList:    make([]*UserAccount, 0),
			UserTenantRoleList: make([]*UserTenantRoles, 0),
		},
	}
	r.HandleFunc("/login", aaa.Authenticate).Methods(http.MethodPost)
	r.HandleFunc("/refresh", aaa.Refresh).Methods(http.MethodPost)

	r.HandleFunc("/user/create", aaa.CreateUser).Methods(http.MethodPost)
	r.HandleFunc("/user/{user}", aaa.ChangeUserPassword).Methods(http.MethodPut)
	r.HandleFunc("/user/{user}", aaa.DeleteUser).Methods(http.MethodDelete)
	r.HandleFunc("/user/{user}", aaa.GetUser).Methods(http.MethodGet)
	r.HandleFunc("/user/s", aaa.SearchUser).Methods(http.MethodGet)

	r.HandleFunc("/tenant/{user}", aaa.UserCreateTenant).Methods(http.MethodPost)
	r.HandleFunc("/tenant/{user}/{oldtenant}/{newtenant}", aaa.UserChangeTenant).Methods(http.MethodPost)
	r.HandleFunc("/tenant/{user}/{tenant}", aaa.UserDeleteTenant).Methods(http.MethodDelete)
	r.HandleFunc("/tenant/{user}", aaa.UserDeleteAllTenant).Methods(http.MethodDelete)
	r.HandleFunc("/tenant/{user}/{tenant}", aaa.UserGetTenant).Methods(http.MethodGet)
	r.HandleFunc("/tenant/{user}", aaa.UserGetAllTenant).Methods(http.MethodGet)
	r.HandleFunc("/tenant/{user}/s", aaa.UserSearchTenant).Methods(http.MethodGet)

	r.HandleFunc("/role/{user}/{tenant}", aaa.UserTenantCreateRole).Methods(http.MethodPost)
	r.HandleFunc("/role/{user}/{tenant}/{role}", aaa.UserTenantDeleteRole).Methods(http.MethodDelete)
	r.HandleFunc("/role/{user}/{tenant}", aaa.UserTenantDeleteAllRole).Methods(http.MethodDelete)
	r.HandleFunc("/role/{user}/{tenant}/{role}", aaa.UserTenantGetRole).Methods(http.MethodGet)
	r.HandleFunc("/role/{user}/{tenant}/s", aaa.UserTenantSearchRole).Methods(http.MethodGet)
}

func WriteResponse(resp http.ResponseWriter, status int, headers map[string][]string, body []byte) {
	if body != nil {
		resp.Write(body)
	}
	resp.WriteHeader(status)
	if headers != nil {
		for hkey, hvarr := range headers {
			for _, hvval := range hvarr {
				resp.Header().Add(hkey, hvval)
			}
		}
	}
}

type TheHandler struct {
	DAO DataAccess
}

func (hdler *TheHandler) Authenticate(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) Refresh(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) CreateUser(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) ChangeUserPassword(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) DeleteUser(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) GetUser(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) SearchUser(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserCreateTenant(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserChangeTenant(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserDeleteTenant(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserDeleteAllTenant(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserGetTenant(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserGetAllTenant(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserSearchTenant(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantCreateRole(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantDeleteRole(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantDeleteAllRole(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantGetRole(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantSearchRole(response http.ResponseWriter, request *http.Request) {
	WriteResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

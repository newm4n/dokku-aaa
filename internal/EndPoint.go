package internal

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strings"
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

func WriteResponse(response http.ResponseWriter, status int, headers map[string][]string, body []byte) {
	if status != http.StatusOK {
		if body == nil {
			logrus.Warnf("[%d]", status)
		} else {
			logrus.Warnf("[%d] %s", status, string(body))
		}
	}
	if headers != nil {
		for headerKey, headerValueArray := range headers {
			for _, headerValue := range headerValueArray {
				response.Header().Add(headerKey, headerValue)
			}
		}
	}
	response.WriteHeader(status)
	if body != nil {
		response.Write(body)
	}
}

type TheHandler struct {
	DAO DataAccess
}

func (hdler *TheHandler) Authenticate(response http.ResponseWriter, request *http.Request) {
	if request.Body == nil {
		WriteResponse(response, http.StatusBadRequest, nil, []byte("missing request body"))
		return
	}
	bodyBytes, err := io.ReadAll(request.Body)
	if err != nil {
		WriteResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("err got %s", err.Error())))
		return
	}
	loginRequest := &AuthenticateRequest{}
	err = json.Unmarshal(bodyBytes, &loginRequest)
	if err != nil {
		WriteResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("canot parse body. got %s", err.Error())))
		return
	}
	at, rt, err := hdler.DAO.Authenticate(request.Context(), loginRequest.Email, loginRequest.Passphrase)
	if err != nil {
		WriteResponse(response, http.StatusUnauthorized, nil, []byte(fmt.Sprintf("unauthorized. got %s", err.Error())))
		return
	}

	authResp := &AuthenticateResponse{
		Access:  at,
		Refresh: rt,
	}

	respOk, err := json.Marshal(authResp)
	if err != nil {
		WriteResponse(response, http.StatusInternalServerError, nil, []byte(fmt.Sprintf("error while generating response. got %s", err.Error())))
		return
	}
	WriteResponse(response, http.StatusOK, map[string][]string{"Content-Type": {"application/json"}}, respOk)
}

func (hdler *TheHandler) Refresh(response http.ResponseWriter, request *http.Request) {
	if request.Body == nil {
		WriteResponse(response, http.StatusBadRequest, nil, []byte("missing request body"))
		return
	}
	bodyBytes, err := io.ReadAll(request.Body)
	if err != nil {
		WriteResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("err got %s", err.Error())))
		return
	}
	refreshRequest := &RefreshRequest{}
	err = json.Unmarshal(bodyBytes, &refreshRequest)
	if err != nil {
		WriteResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("canot parse body. got %s", err.Error())))
		return
	}

	at, err := hdler.DAO.Refresh(request.Context(), refreshRequest.Refresh)
	if err != nil {
		WriteResponse(response, http.StatusUnauthorized, nil, []byte(fmt.Sprintf("unauthorized. got %s", err.Error())))
		return
	}

	refResp := &RefreshResponse{
		Access: at,
	}

	respOk, err := json.Marshal(refResp)
	if err != nil {
		WriteResponse(response, http.StatusInternalServerError, nil, []byte(fmt.Sprintf("error while generating response. got %s", err.Error())))
		return
	}
	WriteResponse(response, http.StatusOK, map[string][]string{"Content-Type": {"application/json"}}, respOk)
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

type UserCreateTenantRequest struct {
}
type UserCreateTenantResponse struct {
}

func (hdler *TheHandler) UserCreateTenant(response http.ResponseWriter, request *http.Request) {
	authorizationValue := request.Header.Get("Authorization")
	if len(authorizationValue) == 0 {
		WriteResponse(response, http.StatusUnauthorized, map[string][]string{"Content-Type": {"text/plain"}}, []byte("missing Authorization header"))
		return
	}

	if !strings.EqualFold(authorizationValue[:7], "Bearer ") {
		WriteResponse(response, http.StatusUnauthorized, map[string][]string{"Content-Type": {"text/plain"}}, []byte("missing Bearer scheme in Authorization header"))
		return
	}

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

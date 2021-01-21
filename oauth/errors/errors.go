package errors

import "net/http"

type RestErr struct {
	Message string `json:"message"`
	Code    int    `json:"status_code"`
	Error   string `json:"error"`
}

func NewBadRequestError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Code:    http.StatusBadRequest,
		Error:   "bad_request",
	}
}

func NewNotFoundError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Code:    http.StatusNotFound,
		Error:   "not_found",
	}
}

func NewUnauthorizedError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Code:    http.StatusUnauthorized,
		Error:   "unauthorized",
	}
}

func NewInternalServerError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Code:    http.StatusInternalServerError,
		Error:   "internal_server_error",
	}
}

func NewConflictError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Code:    http.StatusConflict,
		Error:   "conflict",
	}
}

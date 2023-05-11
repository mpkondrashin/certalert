package sms

import "fmt"

type Error struct {
	code        int
	message     string
	description string
}

func (e Error) Error() string {
	return fmt.Sprintf("%d %s - %s", e.code, e.message, e.description)
}

var (
	ErrUnknown               = &Error{0, "Unknown", "SMS returned unknown error code"}
	ErrBadRequest            = &Error{400, "Bad request", "malformed parameter or request."}
	ErrUnauthorized          = &Error{401, "Unauthorized", "missing or incorrect credentials."}
	ErrNoWebAccessCapability = &Error{403, "No web access capability", "If you receive this message, check the user role capabilities, and enable the Access SMS Web Services capability. On the SMS, go to Admin > Authentication and Authorization > Roles > Edit > Capabilities > Admin > Access SMS Web Services."}
	ErrNotFound              = &Error{404, "Not found", "invalid or nonexistent requested source."}
	ErrPreconditionedFail    = &Error{412, "Preconditioned fail", "unexpected error. Check the SMS System Log. On the SMS, go to Admin > General > SMS System Log."}
	ErrInternalServerError   = &Error{500, "Internal server error", "server-side exception. Check the SMS System Log. On the SMS, go to Admin > General > SMS System Log."}
)

var Errors = map[int]*Error{
	400: ErrBadRequest,
	401: ErrUnauthorized,
	403: ErrNoWebAccessCapability,
	404: ErrNotFound,
	412: ErrPreconditionedFail,
	500: ErrInternalServerError,
}

func ErrByCode(code int) *Error {
	err, ok := Errors[code]
	if ok {
		return err
	}
	return &Error{code, "Unknown", "SMS returned unexpected error code"}
}

package patchvalidator

import (
	"fmt"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/patch"
)

// Validate validates patch.
func Validate(p patch.Patch) error {
	action, err := p.GetAction()
	if err != nil {
		return err
	}

	switch action {
	case patch.JSONPatch:
		return NewJSONValidator().Validate(p)
	case patch.AddPublicKeys:
		return NewAddPublicKeysValidator().Validate(p)
	case patch.AddServiceEndpoints:
		return NewAddServicesValidator().Validate(p)
	case patch.AddAlsoKnownAs:
		return NewAlsoKnownAsValidator().Validate(p)
	}

	return fmt.Errorf(" validation for action '%s' is not supported", action)
}

package outofbandv2

import (
	client "github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
)

// MockClient is a mock out-of-band v2 client used in tests.
type MockClient struct {
	CreateInvVal *outofbandv2.Invitation
	CreateInvErr error
	AcceptInvVal string
	AcceptInvErr error
}

// CreateInvitation mock.
func (m *MockClient) CreateInvitation(opts ...client.MessageOption) (*outofbandv2.Invitation, error) {
	return m.CreateInvVal, m.CreateInvErr
}

// AcceptInvitation mock.
func (m *MockClient) AcceptInvitation(i *outofbandv2.Invitation) (string, error) {
	return m.AcceptInvVal, m.AcceptInvErr
}

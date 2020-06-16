/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"

	"github.com/trustbloc/edge-adapter/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-adapter/test/bdd/pkg/context"
)

const (
	dbPath         = "./.db"
	invitedState   = "invited"
	completedState = "completed"
	timeout        = 5 * time.Second
)

var logger = log.New("aries-framework/tests")

// Steps contains steps for aries agent.
type Steps struct {
	bddContext             *context.BDDContext
	agentCtx               map[string]*ariesctx.Provider
	didExClient            map[string]*didexchange.Client
	didExCompletedFlag     map[string]chan struct{}
	didExInviteHandledFlag map[string]chan struct{}
}

// NewSteps returns new agent steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{
		bddContext:             ctx,
		didExCompletedFlag:     make(map[string]chan struct{}),
		didExInviteHandledFlag: make(map[string]chan struct{}),
		agentCtx:               make(map[string]*ariesctx.Provider),
		didExClient:            make(map[string]*didexchange.Client),
	}
}

// RegisterSteps registers agent steps.
func (d *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running$`, d.CreateAgent)
	s.Step(`^"([^"]*)" responds to connect request from Issuer adapter \("([^"]*)"\)$`, d.handleConnectReq)
}

// CreateAgent with the given parameters.
func (d *Steps) CreateAgent(agentID string) error {
	opts := append([]aries.Option{}, aries.WithStoreProvider(d.getStoreProvider(agentID)))

	// create framework
	err := d.create(agentID, opts...)
	if err != nil {
		return err
	}

	// create didexchange client
	didExClient, err := didexchange.New(d.agentCtx[agentID])
	if err != nil {
		return fmt.Errorf("failed to create new didexchange client: %w", err)
	}

	d.didExClient[agentID] = didExClient

	// auto execute events
	go service.AutoExecuteActionEvent(make(chan service.DIDCommAction))

	// register for message events
	statusCh := make(chan service.StateMsg)
	if err := d.didExClient[agentID].RegisterMsgEvent(statusCh); err != nil {
		return fmt.Errorf("failed to register msg event: %w", err)
	}

	d.didExInviteHandledFlag[agentID] = make(chan struct{})
	d.didExCompletedFlag[agentID] = make(chan struct{})

	go d.eventListener(statusCh, agentID)

	return nil
}

func (d *Steps) handleConnectReq(agentID, issuerID string) error {
	invitationJSON := d.bddContext.Store[bddutil.GetDIDConectRequestKey(issuerID, agentID)]

	invitation := &didexchange.Invitation{}

	err := json.Unmarshal([]byte(invitationJSON), invitation)
	if err != nil {
		return err
	}

	didExClient := d.didExClient[agentID]

	connectionID, err := didExClient.HandleInvitation(invitation)
	if err != nil {
		return err
	}

	select {
	case <-d.didExInviteHandledFlag[agentID]:
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for %s's post state event '%s'", agentID, invitedState)
	}

	err = didExClient.AcceptInvitation(connectionID, "", "")
	if err != nil {
		return err
	}

	//select {
	//case <-d.didExCompletedFlag[agentID]:
	//case <-time.After(timeout):
	//	return fmt.Errorf("timeout waiting for %s's post state event '%s'", agentID, completedState)
	//}

	return nil
}

func (d *Steps) getStoreProvider(agentID string) storage.Provider {
	storeProv := leveldb.NewProvider(dbPath + "/" + agentID + uuid.New().String())
	return storeProv
}

func (d *Steps) create(agentID string, opts ...aries.Option) error {
	const (
		portAttempts  = 5
		listenTimeout = 2 * time.Second
	)

	port := strconv.Itoa(bddutil.GetRandomPort(portAttempts))

	inboundAddr := "localhost:" + port
	externalHost := "docker-host"

	opts = append(opts, defaults.WithInboundHTTPAddr("localhost:"+port, "http://"+externalHost+":"+port))

	out, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
	if err != nil {
		return fmt.Errorf("failed to create http outbound: %w", err)
	}

	opts = append(opts, aries.WithOutboundTransports(out))

	err = d.createFramework(agentID, opts...)
	if err != nil {
		return fmt.Errorf("failed to create new agent: %w", err)
	}

	if err := bddutil.ValidatePort(inboundAddr, listenTimeout); err != nil {
		return err
	}

	logger.Debugf("Agent %s start listening on %s", agentID, inboundAddr)

	return nil
}

func (d *Steps) createFramework(agentID string, opts ...aries.Option) error {
	agent, err := aries.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create new agent: %w", err)
	}

	ctx, err := agent.Context()
	if err != nil {
		return fmt.Errorf("failed to create context: %w", err)
	}

	d.agentCtx[agentID] = ctx

	return nil
}

func (d *Steps) eventListener(statusCh chan service.StateMsg, agentID string) {
	for e := range statusCh {
		err, ok := e.Properties.(error)
		if ok {
			panic(fmt.Sprintf("Service processing failed: %s : %s", agentID, err))
		}

		if e.Type == service.PostState {
			logger.Debugf("%s has received state event for id: %s", agentID, e.StateID)

			switch e.StateID {
			case invitedState:
				d.didExInviteHandledFlag[agentID] <- struct{}{}
			case completedState:
				d.didExCompletedFlag[agentID] <- struct{}{}
			}
		}
	}
}

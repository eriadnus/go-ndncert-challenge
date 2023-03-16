package ca

import (
	"crypto/rand"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"io"
	"ndn/ndncert/challenge/crypto"
	"ndn/ndncert/challenge/schemaold"
	"strings"
	"time"
)

type RequestType int64
type RequestStatus int64
type ChallengeType int64

const (
	BeforeChallenge RequestStatus = iota
	Challenge
	Pending
	Success
	Failure
)

const (
	Probe RequestType = iota
	New
	Revoke
	Renew
)

const (
	Email ChallengeType = iota
)

const caName = "/ndn"
const minimumCertificateComponentSize = 4
const negativeKeyComponentOffset = -4
const keyString = "KEY"

var storage = make(map[string]RequestState)
var availableChallenges = []string{"email"}

type RequestState struct {
	caPrefix enc.Name
	/**
	 * @brief The ID of the request.
	 */
	requestId [8]byte
	/**
	 * @brief The type of the request.
	 */
	requestType RequestType
	/**
	 * @brief The status of the request.
	 */
	status RequestStatus
	/**
	 * @brief The self-signed certificate in the request.
	 */
	cert ndn.Data
	/**
	 * @brief The encryption key for the requester.
	 */
	encryptionKey []byte
	/**
	 * @brief The last Initialization Vector used by the AES encryption.
	 */
	encryptionIv []byte
	/**
	 * @brief The last Initialization Vector used by the other side's AES encryption.
	 */
	decryptionIv []byte
	/**
	 * @brief The challenge type.
	 */
	ChallengeType string
}

func OnNew(i ndn.Interest) spec_2022.Data {
	var requestState RequestState

	appParamReader := enc.NewWireReader(i.AppParam())
	newInt, err := schemaold.ParseCmdNewInt(appParamReader, true)
	if err == nil {
		panic(err.Error())
	}

	certReqReader := enc.NewBufferReader(newInt.CertReq)
	certReqData, _, err := spec_2022.Spec{}.ReadData(certReqReader)
	if err == nil {
		panic(err.Error())
	}

	caPrefixName, err := enc.NameFromStr(caName)
	if !caPrefixName.IsPrefix(certReqData.Name()) {
		panic(err.Error())
	}

	nameComponents := strings.Split(certReqData.Name().String(), "/")
	if len(nameComponents) < minimumCertificateComponentSize {
		panic(err.Error())
	}

	if nameComponents[len(nameComponents)+negativeKeyComponentOffset] != keyString {
		panic(err.Error())
	}

	ecdhState := crypto.NewECDHState(newInt.EcdhPub)
	symmetricKey, salt := crypto.HKDF(ecdhState.GetSharedSecret())

	requestState.requestType = New
	requestState.caPrefix = caPrefixName

	requestId := make([]byte, 8)
	io.ReadFull(rand.Reader, requestId)

	contentType := ndn.ContentTypeBlob
	fourSecondsInNanoseconds := 4 * time.Second

	cmdNewData := schemaold.CmdNewData{
		EcdhPub: ecdhState.PublicKey.Bytes(),
		Salt:    salt, ReqId: requestId,
		Challenge: availableChallenges,
	}

	dataName, _ := enc.NameFromStr(caName)

	cmdNewDataWire := cmdNewData.Encode()

	var requestIdFixed [8]byte
	copy(requestIdFixed[:], requestId)

	storage[string(requestId)] = RequestState{
		caPrefix:      caPrefixName,
		requestId:     requestIdFixed,
		requestType:   New,
		status:        BeforeChallenge,
		cert:          certReqData,
		encryptionKey: symmetricKey,
	}

	return spec_2022.Data{
		NameV: dataName,
		MetaInfo: &spec_2022.MetaInfo{
			ContentType:     utils.ConvIntPtr[ndn.ContentType, uint64](&contentType),
			FreshnessPeriod: &fourSecondsInNanoseconds,
			FinalBlockID:    nil,
		},
		ContentV:       cmdNewDataWire,
		SignatureInfo:  nil,
		SignatureValue: nil,
	}
}

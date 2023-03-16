package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"go.step.sm/crypto/randutil"
	"ndn/ndncert/challenge/crypto"
	"ndn/ndncert/challenge/schemaold"
	"strings"
	"time"
)

type RequestType int64
type RequestStatus uint64
type ChallengeType int64

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
	encryptionKey [16]byte
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

	ChallengeState EmailChallengeState
}

const (
	CaModuleBeforeChallenge RequestStatus = iota
	CaModuleChallenge
	CaModulePending
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
const negativeRequestIdOffset = -2

var storage = make(map[[8]byte]RequestState)
var availableChallenges = []string{"email"}

func OnNew(i ndn.Interest) spec_2022.Data {
	var requestState RequestState

	appParamReader := enc.NewWireReader(i.AppParam())
	newInt, err := schemaold.ParseCmdNewInt(appParamReader, true)
	if err != nil {
		panic(err.Error())
	}

	certReqReader := enc.NewBufferReader(newInt.CertReq)
	certReqData, _, err := spec_2022.Spec{}.ReadData(certReqReader)
	if err != nil {
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

	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()
	ecdhState.SetRemotePublicKey(newInt.EcdhPub)
	salt := make([]byte, sha256.New().Size())
	rand.Read(salt)

	symmetricKey := crypto.HKDF(ecdhState.GetSharedSecret(), salt)

	requestState.requestType = New
	requestState.caPrefix = caPrefixName

	//requestId := make([]byte, 8)
	//io.ReadFull(rand.Reader, requestId)
	_requestId, _ := randutil.Alphanumeric(8)
	requestId := make([]byte, 8)
	copy(requestId, _requestId)

	contentType := ndn.ContentTypeBlob
	fourSeconds := 4 * time.Second

	cmdNewData := schemaold.CmdNewData{
		EcdhPub: ecdhState.PublicKey.Bytes(),
		Salt:    salt, ReqId: requestId[:],
		Challenge: availableChallenges,
	}

	cmdNewDataWire := cmdNewData.Encode()

	var requestIdFixed [8]byte
	var symmetricKeyFixed [16]byte

	copy(requestIdFixed[:], requestId[:])
	copy(symmetricKeyFixed[:], symmetricKey)

	storage[requestIdFixed] = RequestState{
		caPrefix:      caPrefixName,
		requestId:     requestIdFixed,
		requestType:   New,
		status:        CaModuleBeforeChallenge,
		cert:          certReqData,
		encryptionKey: symmetricKeyFixed,
	}

	return spec_2022.Data{
		NameV: i.Name(),
		MetaInfo: &spec_2022.MetaInfo{
			ContentType:     utils.ConvIntPtr[ndn.ContentType, uint64](&contentType),
			FreshnessPeriod: &fourSeconds,
			FinalBlockID:    nil,
		},
		ContentV:       cmdNewDataWire,
		SignatureInfo:  nil,
		SignatureValue: nil,
	}
}

func OnChallenge(i ndn.Interest) spec_2022.Data {
	var requestIdFixed [8]byte

	nameComponents := strings.Split(i.Name().String(), "/")
	requestId := []byte(nameComponents[len(nameComponents)+negativeRequestIdOffset+1])
	copy(requestIdFixed[:], requestId)

	cipherMsgReader := enc.NewWireReader(i.AppParam())
	cipherMsg, err := schemaold.ParseCipherMsg(cipherMsgReader, true)
	if err != nil {
		panic(err.Error())
	}

	var initializationVector [crypto.NonceSizeBytes]byte
	var authenticationTag [crypto.TagSizeBytes]byte

	copy(initializationVector[:], cipherMsg.InitVec)
	copy(authenticationTag[:], cipherMsg.AuthNTag)

	encryptedMsg := crypto.EncryptedMessage{
		initializationVector,
		authenticationTag,
		cipherMsg.Payload,
	}

	requestState := storage[requestIdFixed]

	plaintext := crypto.DecryptPayload(requestState.encryptionKey, encryptedMsg, requestIdFixed)
	plaintextReader := enc.NewBufferReader(plaintext)
	challengeIntPlaintext, err := schemaold.ParseChallengeIntPlain(plaintextReader, true)
	if err != nil {
		println(challengeIntPlaintext)
		panic(err.Error())
	}

	if challengeIntPlaintext.SelectedChal != "email" {
		panic(fmt.Errorf("Only Supports Email Challenge!"))
	}

	emailAddress := string(challengeIntPlaintext.Params[0].ParamValue)
	requestState.ChallengeType = challengeIntPlaintext.SelectedChal

	requestState.ChallengeState = EmailChallengeState{Email: emailAddress}
	if requestState.status == CaModuleBeforeChallenge {
		err := requestState.ChallengeState.InitiateChallenge()
		if err != nil {
			//TODO: Prepare Error Data Packet
		}
		requestState.status = CaModuleChallenge
		challengeStatus := uint64(requestState.ChallengeState.Status)
		remainTries := uint64(requestState.ChallengeState.RemainingAttempts)
		expiry := requestState.ChallengeState.Expiry
		diff := uint64(expiry.Sub(time.Now()).Seconds())
		chalData := schemaold.ChallengeDataPlain{
			Status:      uint64(requestState.status),
			ChalStatus:  &challengeStatus,
			RemainTries: &remainTries,
			RemainTime:  &diff,
		}

		chalDataBuf := chalData.Encode().Join()
		chalDataEncryptedMessage := crypto.EncryptPayload(requestState.encryptionKey, chalDataBuf, requestIdFixed)
		chalDataCiphertext := schemaold.CipherMsg{
			InitVec:  chalDataEncryptedMessage.InitializationVector[:],
			AuthNTag: chalDataEncryptedMessage.AuthenticationTag[:],
			Payload:  chalDataEncryptedMessage.EncryptedPayload,
		}
		chalDataCiphertextBuf := chalDataCiphertext.Encode()
		contentType := ndn.ContentTypeBlob
		fourSeconds := 4 * time.Second
		return spec_2022.Data{
			NameV: i.Name(),
			MetaInfo: &spec_2022.MetaInfo{
				ContentType:     utils.ConvIntPtr[ndn.ContentType, uint64](&contentType),
				FreshnessPeriod: &fourSeconds,
				FinalBlockID:    nil,
			},
			ContentV:       chalDataCiphertextBuf,
			SignatureInfo:  nil,
			SignatureValue: nil,
		}
	}

	if requestState.status == CaModuleChallenge {
		status, err := requestState.ChallengeState.CheckCode(code)
		if status == ChallengeModuleFailure {
			delete(storage, requestId)
			// TODO: Prepare Error Data Packet
		} else if status == ChallengeModuleWrongCode {
			//TODO: Prepare Wrong Code Data Packet
		} else {
			requestState.status = ChallengeModuleSuccess
			//TODO: Issue Certificate
			delete(storage, requestId)
			//TODO: Prepare Success Data Packet
		}
	}
	return spec_2022.Data{}
}

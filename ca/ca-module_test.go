package ca

import (
	"fmt"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/security"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"ndn/ndncert/challenge/crypto"
	"ndn/ndncert/challenge/schemaold"
	"testing"
)

func TestOnNew(t *testing.T) {

	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()

	name, err := enc.NameFromStr("/ndn/bro/pls/KEY/1/version/4")
	if err != nil {
		print(err.Error())
	}
	wire, _, _ := spec_2022.Spec{}.MakeData(
		name,
		&ndn.DataConfig{
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
		},
		nil,
		security.NewSha256Signer(),
	)

	appParams := schemaold.CmdNewInt{
		EcdhPub: ecdhState.PublicKey.Bytes(),
		CertReq: wire.Join(),
	}

	name1, _ := enc.NameFromStr("/ndn/CA/NEW/")

	i := &spec_2022.Interest{
		NameV:                 name1,
		CanBePrefixV:          false,
		MustBeFreshV:          true,
		SignatureInfo:         nil,
		SignatureValue:        nil,
		ApplicationParameters: appParams.Encode(),
	}

	dp := OnNew(i)

	dataBuff := dp.Content().Join()
	dataBuffWireReader := enc.NewBufferReader(dataBuff)
	cmdNewData, err := schemaold.ParseCmdNewData(dataBuffWireReader, true)

	ecdhState.SetRemotePublicKey(cmdNewData.EcdhPub)
	sharedSecret := ecdhState.GetSharedSecret()

	symmetricKey := crypto.HKDF(sharedSecret, cmdNewData.Salt)

	challengeParams := []*schemaold.Param{{
		ParamKey:   "email",
		ParamValue: []byte("tanmaya2000@hotmail.com"),
	}}

	challengeIntPlaintext := schemaold.ChallengeIntPlain{
		SelectedChal: "email",
		Params:       challengeParams,
	}

	var symmetricKeyFixed [16]byte
	var requestIdFixed [8]byte

	copy(symmetricKeyFixed[:], symmetricKey)
	copy(requestIdFixed[:], cmdNewData.ReqId)

	challengeIntPlaintextBytes := challengeIntPlaintext.Encode().Join()

	challengeIntEncryptedMessage := crypto.EncryptPayload(symmetricKeyFixed, challengeIntPlaintextBytes, requestIdFixed)
	cipherMsgInt := schemaold.CipherMsg{
		InitVec:  challengeIntEncryptedMessage.InitializationVector[:],
		AuthNTag: challengeIntEncryptedMessage.AuthenticationTag[:],
		Payload:  challengeIntEncryptedMessage.EncryptedPayload,
	}

	name2, _ := enc.NameFromStr(fmt.Sprintf("/ndn/CA/CHALLENGE/%s", cmdNewData.ReqId))
	ichal := &spec_2022.Interest{
		NameV:                 name2,
		CanBePrefixV:          false,
		MustBeFreshV:          true,
		SignatureInfo:         nil,
		SignatureValue:        nil,
		ApplicationParameters: cipherMsgInt.Encode(),
	}

	dpchal := OnChallenge(ichal)

	println(dpchal.Name().String())

	codeParams := []*schemaold.Param{{
		ParamKey:   "code",
		ParamValue: []byte("123456"),
	}}

	codeIntPlaintext := schemaold.ChallengeIntPlain{
		SelectedChal: "email",
		Params:       codeParams,
	}

	codeIntPlaintextBytes := codeIntPlaintext.Encode().Join()

	codeIntEncryptedMessage := crypto.EncryptPayload(symmetricKeyFixed, codeIntPlaintextBytes, requestIdFixed)
	codeMsgInt := schemaold.CipherMsg{
		InitVec:  codeIntEncryptedMessage.InitializationVector[:],
		AuthNTag: codeIntEncryptedMessage.AuthenticationTag[:],
		Payload:  codeIntEncryptedMessage.EncryptedPayload,
	}

	name3, _ := enc.NameFromStr(fmt.Sprintf("/ndn/CA/CHALLENGE/%s", cmdNewData.ReqId))
	icode := &spec_2022.Interest{
		NameV:                 name3,
		CanBePrefixV:          false,
		MustBeFreshV:          true,
		SignatureInfo:         nil,
		SignatureValue:        nil,
		ApplicationParameters: codeMsgInt.Encode(),
	}

	OnChallenge(icode)
}

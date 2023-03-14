package Challenge

import (
	"math/rand"
	"time"
)

var maxAttempts uint = 5

const (
	secretLifetime int64 = 300 // in seconds
	secretLength   int   = 5
)

type ChallengeState struct {
	remainingAttempts uint
	expiry            time.Time
	status            int
}

type EmailChallenge struct {
	EmailChallengeInf
	ChallengeState
	email      string
	secretCode string
}

type EmailChallengeInf interface {
	generateSecretCode() uint
	InitiateChallenge(email string) string
	CheckCode(secret uint) (bool, string)
	//HandleChallengeRequest() (string, )
	GetChallengeStatus() int
	sendEmail()
}

func (e EmailChallenge) InitiateChallenge() string {
	if e.status != 0 {
		return "Challenge Already Initiated"
	}

	e.status = 1
	e.secretCode = e.generateSecretCode()
	e.remainingAttempts = maxAttempts
	e.expiry = time.Now().Add(time.Second * time.Duration(secretLifetime))
	return "Challenge Initiated"
	//sendEmail
}

func (e EmailChallenge) CheckCode(secret string) (bool, string) {
	if e.status != 1 && e.status != 2 {
		return false, "Invalid state for challenge"
	} else if time.Now().After(e.expiry) {
		e.status = 5
		return false, "Challenge Expired"
	} else if secret != e.secretCode {
		if e.remainingAttempts > 1 {
			e.status = 3
			e.remainingAttempts -= 1
			return false, "Incorrect Secret Code"
		} else {
			e.status = 4
			return false, "Incorrect Secret Code: No Tries Left"
		}
	} else {
		e.status = 6
		return true, "Challenge Successful"
	}
}

func (e EmailChallenge) generateSecretCode() string {

	var digits = []rune("0123456789")
	b := make([]rune, secretLength)
	for i := range b {
		b[i] = digits[rand.Intn(len(digits))]
	}
	return string(b)
}

func (e EmailChallenge) sendEmail() {
 
}
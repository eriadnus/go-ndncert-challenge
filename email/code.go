package email

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net/mail"
	"net/smtp"
	"os"
	"regexp"
)

const SmtpConfigFilePath = "../config/smtp.yml"

type Status int

type SMTPAuth struct {
	Smtp struct {
		identity string
		username string
		password string
		host     string
		port     int64
	}
}

type CodeEmail struct {
	ChallengeEmail string
	ChallengeCode  string
}

const (
	Success Status = iota
	Invalid
	Error
)

func readSmtpConfig() (*SMTPAuth, error) {
	buf, err := os.ReadFile(SmtpConfigFilePath)
	if err != nil {
		return nil, err
	}

	c := &SMTPAuth{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %w", SmtpConfigFilePath, err)
	}

	return c, err
}

func NewCodeEmail(e string, c string) (CodeEmail, Status, error) {
	_, emailErr := mail.ParseAddress(e)
	if emailErr != nil {
		return CodeEmail{}, Invalid, fmt.Errorf("invalid email address %s: failed to match regex", e)
	}

	_, codeErr := regexp.MatchString("^\\d{6}$", c)
	if codeErr != nil {
		return CodeEmail{}, Invalid, fmt.Errorf("invalid code %s: failed to match regex", c)
	}

	return CodeEmail{e, c}, Success, nil
}

func (c CodeEmail) SendCodeEmail() (Status, error) {
	conf, readSmtpConfigErr := readSmtpConfig()
	if readSmtpConfigErr != nil {
		return Error, fmt.Errorf("failed to read config file from path: %s", SmtpConfigFilePath)
	}

	address := fmt.Sprintf("%s:%d", conf.Smtp.host, conf.Smtp.port)
	auth := smtp.PlainAuth(conf.Smtp.identity, conf.Smtp.username, conf.Smtp.password, conf.Smtp.host)
	from := conf.Smtp.identity
	to := []string{c.ChallengeEmail}
	subject := "Subject: Your NDN Email Challenge Secret Pin\n"
	body := fmt.Sprintf("Secret  PIN: %s", c.ChallengeCode)
	message := []byte(subject + body)

	sendMailErr := smtp.SendMail(address, auth, from, to, message)
	if sendMailErr != nil {
		return Error, fmt.Errorf("failed to send code challenge email to %s", string(c.ChallengeEmail))
	}

	return Success, nil
}

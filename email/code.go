package email

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net/mail"
	"net/smtp"
	"os"
)

const SmtpConfigFilePath = "../config/smtp.yml"

type Email string
type Code string
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
	ChallengeEmail Email
	ChallengeCode  Code
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

func NewCodeEmail(e Email, c Code) (CodeEmail, Status, error) {
	_, err := mail.ParseAddress(string(e))
	if err != nil {
		return CodeEmail{}, Invalid, fmt.Errorf("invalid email address %s: failed to match regex", e)
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
	to := []string{string(c.ChallengeEmail)}
	subject := "Subject: Your NDN Email Challenge Secret Pin\n"
	body := fmt.Sprintf("Secret  PIN: %s", c.ChallengeCode)
	message := []byte(subject + body)

	sendMailErr := smtp.SendMail(address, auth, from, to, message)
	if sendMailErr != nil {
		return Error, fmt.Errorf("failed to send code challenge email to %s", string(c.ChallengeEmail))
	}

	return Success, nil
}

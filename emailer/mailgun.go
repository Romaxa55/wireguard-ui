package emailer

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/mailgun/mailgun-go/v4"
)

type MailgunApiMail struct {
	domain   string
	apiKey   string
	fromName string
	from     string
	baseApi  string
}

func NewMailgunApiMail(domain, apiKey, fromName, from, baseApi string) *MailgunApiMail {
	ans := MailgunApiMail{domain: domain, apiKey: apiKey, fromName: fromName, from: from, baseApi: baseApi}
	return &ans
}

func (o *MailgunApiMail) Send(toName string, to string, subject string, content string, attachments []Attachment) error {
	mg := mailgun.NewMailgun(o.domain, o.apiKey)
	mg.SetAPIBase(o.baseApi)
	m := mg.NewMessage(
		o.from,
		subject,
		content,
		to,
	)

	for i := range attachments {
		encoded := base64.StdEncoding.EncodeToString(attachments[i].Data)
		m.AddBufferAttachment(attachments[i].Name, []byte(encoded))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err := mg.Send(ctx, m)
	return err
}

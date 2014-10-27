package imap

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/googollee/go-encoding"
)

const (
	RFC822       = "(RFC822)"
	RFC822Header = "RFC822.HEADER"
	RFC822Text   = "RFC822.TEXT"
	RFC822Size   = "RFC822.SIZE"
	Seen         = "\\Seen"
	Deleted      = "\\Deleted"
	Inbox        = "INBOX"
)

type IMAPClient struct {
	conn  *tls.Conn
	count int
	buf   []byte
}

type IMAPResponse struct {
	Body   string
	Length int
	Value  int
	Type   string
}

func NewClient(conn net.Conn, hostname string) (*IMAPClient, error) {
	config := tls.Config{
		ServerName: hostname,
	}
	c := tls.Client(conn, &config)
	buf := make([]byte, 1024)
REPLY:
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		for _, i := range buf[:n] {
			if i == byte('\n') {
				break REPLY
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return &IMAPClient{
		conn: c,
		buf:  buf,
	}, nil
}

func (c *IMAPClient) Close() error {
	return c.conn.Close()
}

func (c *IMAPClient) Do(cmd string) *Response {
	c.count++
	cmd = fmt.Sprintf("a%03d %s\r\n", c.count, cmd)
	ret := NewResponse()

	_, err := c.conn.Write([]byte(cmd))
	if err != nil {
		ret.err = err
		return ret
	}

	for {
		n, err := c.conn.Read(c.buf)
		if err != nil {
			ret.err = err
			return ret
		}
		isFinished, err := ret.Feed(c.buf[:n])
		if err != nil {
			ret.err = err
			return ret
		}
		if isFinished {
			break
		}
	}
	return ret
}

func (c *IMAPClient) Login(user, password string) error {
	resp := c.Do(fmt.Sprintf("LOGIN %s %s", user, password))
	return resp.err
}

// TODO fix this to return error
func (c *IMAPClient) Select(box string) *Response {
	return c.Do(fmt.Sprintf("SELECT %s", box))
}

func (c *IMAPClient) Search(flag string) ([]string, error) {
	resp := c.Do(fmt.Sprintf("SEARCH %s", flag))
	if resp.Error() != nil {
		return nil, resp.Error()
	}
	for _, reply := range resp.Replys() {
		org := reply.Origin()
		if len(org) >= 6 && strings.ToUpper(org[:6]) == "SEARCH" {
			ids := strings.Trim(org[6:], " \t\n\r")
			if ids == "" {
				return nil, nil
			}
			return strings.Split(ids, " "), nil
		}
	}
	return nil, errors.New("invalid response")
}

func (c *IMAPClient) Status(box string, arg string) error {
	resp := c.Do(fmt.Sprintf("STATUS %s %s", box, arg))
	if resp.Error() != nil {
		return resp.Error()
	}

	return nil
}

func (c *IMAPClient) Create(box string) error {
	resp := c.Do(fmt.Sprintf("CREATE %s", box))
	if resp.Error() != nil {
		return resp.Error()
	}

	return nil
}

func (c *IMAPClient) Subscribe(box string) error {
	resp := c.Do(fmt.Sprintf("SUBSCRIBE %s", box))
	if resp.Error() != nil {
		return resp.Error()
	}

	return nil
}

func (c *IMAPClient) Fetch(id, arg string) (*IMAPResponse, error) {
	resp := c.Do(fmt.Sprintf("FETCH %s %s", id, arg))
	if resp.Error() != nil {
		return nil, resp.Error()
	}
	for _, reply := range resp.Replys() {
		org := reply.Origin()
		if len(org) < len(id) || org[:len(id)] != id {
			continue
		}
		org = org[len(id)+1:]
		if len(org) >= 5 && strings.ToUpper(org[:5]) == "FETCH" {
			body := reply.Content()
			length, _ := reply.Length()
			value, _ := reply.Value()
			response := &IMAPResponse{body, length, value, reply.Type()}
			return response, nil
		}
	}
	return nil, errors.New("invalid response")
}

func (c *IMAPClient) GetMessageSize(id string) (int, error) {
	resp, err := c.Fetch(id, RFC822Size)
	if err != nil {
		return 0, err
	}

	return resp.Value, nil
}

func (c *IMAPClient) StoreFlag(id, flag string) error {
	resp := c.Do(fmt.Sprintf("STORE %s FLAGS %s", id, flag))
	return resp.Error()
}

func (c *IMAPClient) StoreAddFlag(id, flag string) error {
	resp := c.Do(fmt.Sprintf("STORE %s +FLAGS %s", id, flag))
	return resp.Error()
}

func (c *IMAPClient) Copy(id, dst string) error {
	resp := c.Do(fmt.Sprintf("COPY %s %s", id, dst))
	return resp.Error()
}

func (c *IMAPClient) Expunge() ([]string, error) {
	resp := c.Do("EXPUNGE")
	if resp.Error() != nil {
		return nil, resp.Error()
	}
	expunged := []string{}
	for _, reply := range resp.Replys() {
		org := reply.Origin()
		exp := strings.Split(org, " ")
		if len(exp) == 2 && exp[1] == "EXPUNGE" {
			expunged = append(expunged, exp[0])
		}
	}
	return expunged, nil
}

func (c *IMAPClient) Logout() error {
	resp := c.Do("LOGOUT")
	return resp.Error()
}

func (c *IMAPClient) GetMessage(id string) (*mail.Message, error) {
	headerResp := c.Do(fmt.Sprintf("FETCH %s %s", id, RFC822Header))
	if headerResp.Error() != nil {
		return nil, headerResp.Error()
	}

	replys := headerResp.Replys()

	reader := textproto.NewReader(bufio.NewReader(bytes.NewBuffer(replys[0].content)))
	header, err := reader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	bodyResp := c.Do(fmt.Sprintf("FETCH %s %s", id, RFC822Text))
	if bodyResp.Error() != nil {
		return nil, bodyResp.Error()
	}

	return &mail.Message{
		Header: mail.Header(header),
		Body:   bytes.NewBuffer(bodyResp.Replys()[0].content),
	}, nil
}

func ParseAddress(str string) ([]*mail.Address, error) {
	inQuote := false
	lastStart := 0
	strs := make([]string, 0, 0)
	for i, c := range str {
		switch c {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				strs = append(strs, str[lastStart:i])
				lastStart = i + 1
			}
		}
	}
	strs = append(strs, str[lastStart:len(str)])
	ret := make([]*mail.Address, len(strs), len(strs))
	for i, s := range strs {
		if s[len(s)-1] == '>' {
			split := strings.LastIndex(s, "<")
			name := strings.Trim(s[:split], "\" ")
			addr := s[split:]
			if name[0] == '=' {
				// data, charset, err := encoding.DecodeEncodedWord(name)
				data, err := encoding.DecodeEncodedWord(name)
				if err != nil {
					return nil, fmt.Errorf("address %d invalid: %s", i, err)
				}
				// data, err = encoding.Conv(data, "UTF-8", charset)
				data, err = encoding.Conv(data, "UTF-8", "x")
				if err != nil {
					return nil, fmt.Errorf("address %d convert charset error: %s", i, err)
				}
				ret[i] = &mail.Address{
					Name:    data,
					Address: strings.Trim(addr, "<>"),
				}
			} else {
				ret[i] = &mail.Address{
					Name:    strings.Trim(name, "\""),
					Address: strings.Trim(addr, "<>"),
				}
			}
		} else {
			ret[i] = &mail.Address{
				Address: s,
			}
		}
	}
	return ret, nil
}

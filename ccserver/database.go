package main

import (
	"database/sql"
	"errors"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func DatabaseInit() (*sql.DB, error) {
	if _, err := os.Stat("database.db"); err == nil {
		db, err := sql.Open("sqlite3", "database.db")
		if err != nil {
			return nil, err
		}
		return db, nil
	} else if errors.Is(err, os.ErrNotExist) {
		file, err := os.Create("database.db")
		file.Close()
		if err != nil {
			return nil, err
		}
		db, err := sql.Open("sqlite3", "database.db")
		if err != nil {
			return nil, err
		}
		err = DatabaseCreate(db)
		if err != nil {
			return nil, err
		}
		return db, nil
	} else {
		return nil, err
	}
}

func DatabaseCreate(db *sql.DB) error {
	listener_table := `CREATE TABLE listeners (
        Id TEXT NOT NULL PRIMARY KEY,
        "Name" TEXT,
        "Attacker" TEXT,
        "AttackerPassword" TEXT,
        "AttackerUrl" TEXT,
		"AttackerDomain" TEXT,
		"Victim" TEXT,
		"VictimPassword" TEXT,
		"VictimUrl" TEXT,
		"VictimDomain" TEXT,
		"Key" TEXT);`
	query, err := db.Prepare(listener_table)
	if err != nil {
		// fmt.Println(err)
		return err
	}
	query.Exec()
	target_table := `CREATE TABLE targets (
        Id TEXT NOT NULL PRIMARY KEY,
        "Ip" TEXT,
        "SystemInfo" TEXT,
		"User" TEXT,
		"IdListener" TEXT);`
	query, err = db.Prepare(target_table)
	if err != nil {
		// fmt.Println(err)
		return err
	}
	query.Exec()

	return nil
}

package config

import (
	"fmt"

	"database/sql"

	"github.com/spf13/viper"

	_ "github.com/go-sql-driver/mysql"
)

//Getting database information
func GetDB() (db *sql.DB, err error) {

	//Create a config.json file in the path $HOME/config/config.json
	viper.SetConfigName("config")
	viper.AddConfigPath("$HOME/config/")
	err1 := viper.ReadInConfig()
	if err1 != nil {
		fmt.Println("Couldn't read config file")
	}

	//Grabbing db credentials from config.json file
	dbUser := viper.GetString("dbuser")
	dbPass := viper.GetString("dbpass")
	dbname := viper.GetString("db")
	dbtype := viper.GetString("dbtype")

	db, err = sql.Open(dbtype, dbUser+":"+dbPass+"@(localhost)/"+dbname)

	return
}

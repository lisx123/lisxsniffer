package main

import (
	"fmt"
	"reflect"
)

type User struct {
	Id   int
	Name string
	//addr string
}

func main() {
	u := User{Id: 1001, Name: "xxx" /*, addr:"xxx"*/}
	t := reflect.TypeOf(u)
	v := reflect.ValueOf(u)

	for k := 0; k < t.NumField(); k++ {
		fmt.Printf("%s  ---  %s\n", t.Field(k).Name, v.Field(k).Interface())
	}
}

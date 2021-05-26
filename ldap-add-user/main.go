/*
Golang and openldap example






*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/mux"
)

// User LDAP Attributes
type openldapAttributes struct {
	Cn        string `json:"cn"`
	Pass      string `json:"pass"`
	FirstNAME string `json:"firstNAME"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

type changePassLDAP struct {
	Cn      string `json:"cn"`
	OldPass string `json:"oldPass"`
	NewPass string `json:"NewPass"`
}

func main() {
	//addLDAPUser()
	router := mux.NewRouter()
	// Login Route
	router.HandleFunc("/login", loginAPI).Methods("POST")
	// AddUSER route
	router.HandleFunc("/addNewUserToLDAP", addNewUserToLdap).Methods("POST")
	// Chnage password URL
	router.HandleFunc("/chnagePassLDAP", middlewareAuth(http.HandlerFunc(passwordChnageAPI))).Methods("POST")

	log.Println("server started and listening on http://127.0.0.1:8080")
	http.ListenAndServe("127.0.0.1:8080", router)
}

// func addNewUser(w http.ResponseWriter, r *http.Request) {
// 	// fmt.Println("HIT")
// 	// fmt.Println(mux.Vars(r))
// 	addLDAPUser(w, r)
// }

// Login API
func loginAPI(w http.ResponseWriter, r *http.Request) {
	// Setting up requied vaibales
	var username string
	var passowrd string
	var ok bool

	// Assign the requied values to the variables
	// func (r *Request) BasicAuth() (username, password string, ok bool)
	username, passowrd, ok = r.BasicAuth()

	if !ok {
		fmt.Println("Error parsing basic auth")
		w.WriteHeader(401)
		return
	} else {
		if AuthenticateLDAP(username, passowrd) {
			w.WriteHeader(200)
			body := "done"
			w.Write([]byte(body))
			return
		} else {
			fmt.Println("Error parsing basic auth")
			w.WriteHeader(401)
			body := "Error parsing basic auth"
			w.Write([]byte(body))
			return
		}
	}
}

// Authentication LDAP server based on DN
// DN: cn=sagnik.sarkar,ou=AppUSER,ou=People,dc=isabellasoft,dc=com
// passowrd: testpassword
// authenticate users under ou=Appuser
func AuthenticateLDAP(cn string, pass string) bool {
	var result bool = false
	ldapURL := "ldap://172.17.0.1:389"
	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		//log.Fatal(err)
		log.Println(err)
	} else {
		result = true
	}
	err = l.Bind("cn="+cn+",ou=AppUSER,ou=People,dc=isabellasoft,dc=com", pass)
	if err != nil {
		//log.Fatal(err)
		log.Println(err)
		result = false
	} else {
		result = true
	}
	defer l.Close()
	return result
}

/*
Example
{
    "cn": "sagnik.sarkar",
    "pass": "testPassowrd",
    "firstNAME": "sagnik",
    "lastName": "sarkar",
    "email": "sagnik.sarkar@gmail.com"
}
*/

func addNewUserToLdap(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Context-Type", "application/json")
	var newUSER openldapAttributes
	_ = json.NewDecoder(r.Body).Decode(&newUSER)

	//fmt.Println(newUSER.Cn)

	// Connect to openLDAP as Admin
	ldapConnection, err := ldap.DialURL("ldap://172.17.0.1:389")
	if err != nil {
		log.Fatal(err)
	}
	defer ldapConnection.Close()

	err = ldapConnection.Bind("cn=admin,dc=isabellasoft,dc=com", "admin")
	if err != nil {
		log.Fatal(err)
	}

	addReq := ldap.NewAddRequest("cn="+newUSER.Cn+",ou=AppUSER,ou=People,dc=isabellasoft,dc=com", []ldap.Control{})
	addReq.Attribute("objectClass", []string{"top", "inetOrgPerson", "organizationalPerson", "person"})
	addReq.Attribute("initials", []string{"passwordSaverUser"})
	addReq.Attribute("givenName", []string{newUSER.FirstNAME})
	addReq.Attribute("sn", []string{newUSER.LastName})
	addReq.Attribute("mail", []string{newUSER.Email})
	addReq.Attribute("userPassword", []string{newUSER.Pass})

	// Add the user to LDAP
	if addTOLDAP(addReq, ldapConnection) {
		w.WriteHeader(200)
		body := "Done"
		w.Write([]byte(body))
	} else {
		fmt.Printf("HIT ERROR")
		w.WriteHeader(409)
		body := "User Exists"
		w.Write([]byte(body))
	}
}

func addTOLDAP(addRequest *ldap.AddRequest, l *ldap.Conn) bool {
	result := false
	err := l.Add(addRequest)
	if err != nil {
		fmt.Println("Entry NOT done", err)
	} else {
		result = true
		fmt.Println("Entry DONE", err)
	}
	return result
}

func passwordChnageAPI(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Context-Type", "application/json")
	var passwordChnageDetails changePassLDAP
	_ = json.NewDecoder(r.Body).Decode(&passwordChnageDetails)

	passChangeOnLDAP(passwordChnageDetails, w)

}

/*
 Example
 {
     "cn": "agnik.sarkar",
     "oldPass": "testPassowrd",
     "NewPass": "newpassword"
 }
*/
func passChangeOnLDAP(passDetails changePassLDAP, w http.ResponseWriter) {
	// Connect to openLDAP as Admin
	ldapConnection, err := ldap.DialURL("ldap://172.17.0.1:389")
	if err != nil {
		log.Fatal(err)
	}
	defer ldapConnection.Close()

	err = ldapConnection.Bind("cn=admin,dc=isabellasoft,dc=com", "admin")
	if err != nil {
		log.Fatal(err)
	}
	modReq := ldap.NewModifyRequest("cn="+passDetails.Cn+",ou=AppUSER,ou=People,dc=isabellasoft,dc=com", []ldap.Control{})
	modReq.Replace("userPassword", []string{passDetails.NewPass})

	if err := ldapConnection.Modify(modReq); err != nil {
		log.Fatal("error setting user password:", modReq, err)
	} else {
		w.WriteHeader(200)
		body := "Done"
		w.Write([]byte(body))
	}
}

func middlewareAuth(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing Auth MiddleWare")

		username, passowrd, ok := r.BasicAuth()

		if !ok {
			log.Fatal("STOP")
		} else {
			if AuthenticateLDAP(username, passowrd) {
				next.ServeHTTP(w, r)
			} else {
				log.Fatal("STOP")
			}
		}
	})
}

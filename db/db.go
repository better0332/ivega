package db

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"log"
	// "time"
)

var db *sql.DB

/*var stmtQueryId *sql.Stmt
var stmtQuery *sql.Stmt
var stmtInsert *sql.Stmt*/

type Data struct {
	Id     int
	Scheme string
	Method string
	Host   string
	Path   string
	Req    []byte
}

func init() {
	var err error

	db, err = sql.Open("mysql", "root:mysql12345+@(127.0.0.1:3306)/WebHunter?charset=utf8")
	if err != nil {
		panic(err)
	}
	db.SetMaxIdleConns(5)
	/*if stmtQueryId, err = db.Prepare(`select id, scheme, method, host, path, req
		from info where id>=? and id<=?`); err != nil {
		panic(err)
	}
	if stmtQuery, err = db.Prepare(`select id, scheme, method, host, path, req
		from info`); err != nil {
		panic(err)
	}
	if stmtInsert, err = db.Prepare(`insert into vul values(?, ?, ?, ?, ?, NOW())`); err != nil {
		panic(err)
	}*/
}

func Query(a, b int, host, domain string, auto bool) (d []*Data) {
	// defer stmtQueryId.Close()
	// defer stmtQuery.Close()

	var rows *sql.Rows
	var err error

	/*if a == 0 && b == 0 {
		if rows, err = stmtQuery.Query(); err != nil {
			log.Println(err)
			return
		}
	} else {
		if rows, err = stmtQueryId.Query(a, b); err != nil {
			log.Println(err)
			return
		}
	}*/

	if a == 0 && b == 0 {
		sql := `select id, scheme, method, host, path, req from info`

		if host == "" {
			if domain == "" {
				if auto {
					sql += ` where count=0`
				}

				sql += ` order by id`
				if rows, err = db.Query(sql); err != nil {
					log.Println(err)
					return
				}
			} else {
				if auto {
					sql += ` where domain=? and count=0`
				} else {
					sql += ` where domain=?`
				}

				sql += ` order by id`
				if rows, err = db.Query(sql, domain); err != nil {
					log.Println(err)
					return
				}
			}
		} else {
			if auto {
				sql += ` where host=? and count=0`
			} else {
				sql += ` where host=?`
			}

			sql += ` order by id`
			if rows, err = db.Query(sql, host); err != nil {
				log.Println(err)
				return
			}
		}
	} else {
		if host == "" {
			if domain == "" {
				if rows, err = db.Query(`select id, scheme, method, host, path, req
				from info where id>=? and id<=? order by id`, a, b); err != nil {
					log.Println(err)
					return
				}
			} else {
				if rows, err = db.Query(`select id, scheme, method, host, path, req
				from info where domain=? and id>=? and id<=? 
				order by id`, a, b, domain); err != nil {
					log.Println(err)
					return
				}
			}
		} else {
			if rows, err = db.Query(`select id, scheme, method, host, path, req
				from info where host=? and id>=? and id<=? 
				order by id`, a, b, host); err != nil {
				log.Println(err)
				return
			}
		}
	}

	defer rows.Close()

	for rows.Next() {
		data := new(Data)
		if err := rows.Scan(&data.Id, &data.Scheme, &data.Method, &data.Host,
			&data.Path, &data.Req); err != nil {
			log.Println(err)
			return
		}
		d = append(d, data)
	}
	return
}

func Insert(id, vultype int, sig, req, resp string) {
	/*if _, err := stmtInsert.Exec(id, vultype, sig, req, resp); err != nil {
		log.Println(err)
	}*/
	if _, err := db.Exec(`insert into vul values(?, ?, ?, ?, ?, NOW())`,
		id, vultype, sig, req, resp); err != nil {
		log.Println(err)
	}
}

func Update(id int) {
	if _, err := db.Exec(`update info set count=count+1 where id=?`, id); err != nil {
		log.Println(err)
	}
}

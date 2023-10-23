# golang-basic-cred

Some basic credential handling functionality. 

Allows to (see ./library/func.go and ./library/structs.go) ...

- store credentials in a local SQLite database (using hashing, salt and pepper)
  - including db creation
  - schema creation
  - read and write from/to db   
- create random credentials
- check credentials 
- read in passwords from terminal


# Build Binary / Build Credentials-Manager

```
go build ./exec/credmanager/
```


# ToDos

1) Repair build pipeline - ok
2) Sonatype
3) TestCoverage

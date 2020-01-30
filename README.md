# Introduction

This project is about how to use spring security username/password from database and exchanging token using JWT 

This is Spring Boot V2 Application for Securing a REST API with JSON Web Token (JWT). 
See more details : https://medium.com/@sopheamak/springboot-security-with-jwt-fca1446790ba

# Technologies

- Spring boot 2 
- JWT jjwt
- Mysql
- Database JPA

# REST APIs
- Register new user

````
curl -X POST \
  http://localhost:8080/register \
  -H 'content-type: application/json' \
  -d '{
"username":"test",
"password":"password"
}'
````

- Login API to exchange token

````
curl -X POST \
  http://localhost:8080/auth/token \
  -H 'content-type: application/json' \
  -d '{
"username":"test",
"password":"password"
}'

response back 

{
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0IiwiUk9MRVMiOlsiUk9MRV9VU0VSIl0sImV4cCI6MTU3ODE3ODI5NSwiaWF0IjoxNTc4MTYwMjk1fQ.gDMuDfp1_1kv729HrOWCskTm4rNCm7SSoniqDHZuRD5H1uUtFzbiktN9NVaTNaTvp14UqGavQygKhO3pTFOQJg"
}
````
- None Login API
curl http://localhost:8080/test

- Login API
curl http://locathost:8080/secure

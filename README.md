# AUTH SERVER WITH GOLANG

## Overview

Simple auth server to authenticate user and create a cookie for further authentications:

- /login: Returns login.html
- /register: POST request to register user (no html form provided)

### Installation

```sh
# go 1.18+
go run main.go
```

### Docker

```
docker build -t go-auth-server -f build\Dockerfile .
docker run --rm -p 5000:5000 go-auth-server
```

### Kubernetes

1. Create a development cluster inside Docker Desktop

```
kind create cluster --name auth-server-cluster
```

2. Apply deployment configuration file

```
kubectl apply -f build\deployment.yaml
```

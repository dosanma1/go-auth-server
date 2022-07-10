# AUTH SERVER WITH GOLANG

## Overview

Simple web server with 3 routes:

- /: Returns index.html
- /form.html: Returns form.html
- /hello: Returns a "Hello"

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

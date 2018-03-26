# go-tmp-crypt

---

Golang web application to store encrypted files with an expiration date

## Docker

```bash
$ git clone https://github.com/smolveau/go-tmp-crypt.git
$ cd go-tmp-crypt
$ docker-compose down
$ docker-compose up -d --build
```

Service will be available on localhost:9090 (if you don't use Virtual Box).

Otherwise, it will be available on the IP of the VM:9090.
You can find it via kitematic: launch it, then take the IP address of the VM **"go_tmpcrypt_web"**.

### Stack

* Go(lang)
* Goland IDE by JetBrains
* PostgreSQL
* Docker

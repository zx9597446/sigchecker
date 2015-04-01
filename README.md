# sigchecker
an signature checker middleware for [go-json-rest]( https://github.com/ant0ine/go-json-rest )

# purpose
some API services only provided for authorized clients, this middleware verify an signature in request header, both client side and server side must use same secret key to generate/check signature

# install
--------------

	go get -u github.com/zx9597446/sigchecker

# use this middleware with [go-json-rest](https://github.com/ant0ine/go-json-rest)

```
	secret := "abcd"
	headerKey := "X-request-signature"
	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	api.Use(NewSignatureChecker(headerKey, secret))
```

# how to make request on client side

formation of signature is:

	timestamp,signature

to generate signature:

	signature = md5(timestamp + secret)

API doc
------------
see [doc](http://godoc.org/github.com/zx9597446/sigchecker)

examples
-----------
see [test](http://github.com/zx9597446/sigchecker/blob/master/checker_test.go)

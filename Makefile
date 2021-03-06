all:
	go build ./cmd/curve-audit

test:
	@for i in $$(find . -name '*_test.go' | xargs -n1 dirname | uniq); do \
		go test -timeout=3s "$$i" || exit 1; \
	done

clean:
	rm -f curve-client

fmt:
	go fmt ./...

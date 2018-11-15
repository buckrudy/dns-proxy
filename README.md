## A simple dns proxy server

reqire library: `libcares`, `libev`

`CentOS`:
	`yum install c-ares-devel libev-devel`

### Compile
`make`


### Test

1. start dns proxy server
	`./dns_proxy 53 8.8.8.8`

2. start test client
	`./test 127.0.0.1`


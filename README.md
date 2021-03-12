# publicip.is

Dead simple HTTP server that returns the client's IP, written in pure C.
Supports IPv6 and IPv4.

Hosted right now at http://publicip.is

# Usage

`./publicip.is <listen-port> <num-threads (optional, default is number of cores)>`

# Complilation

Just run `make`

`make debug` and `make release` are supported, release is default.

I also have a meson build in case I want to add anything complicated like
profiling in the future:

`meson build`
`mescon compile -C build`



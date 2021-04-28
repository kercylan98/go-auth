module github.com/kercylan98/kkit-auth

go 1.16

require (
	github.com/go-redis/redis v6.15.9+incompatible // indirect
	github.com/kercylan98/kkit-core v0.0.0-20210426084449-5aa215579260
	github.com/kercylan98/kkit-session v0.0.0-20210427145356-3696f379aa4b
)

replace (
	github.com/kercylan98/kkit-session => "../kkit-session"
)
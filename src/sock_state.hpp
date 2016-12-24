#pragma once
enum class sock_state:int {
	SOCK_CLOSED,
	SOCK_OPEN,
	SOCK_KEEPALIVE,
	SOCK_EAGAIN=-EAGAIN
};

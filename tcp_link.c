#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

#include <config.h>
#define __BSD_VISIBLE 1
#include <bsdinet/tcp.h>
#include <bsdinet/tcpup.h>
#include <base_link.h>

#define SEQ_LT(a, b) ((int)((a) - (b)) < 0)

// iptables -A PREROUTING -t raw -p tcp -m tcp --dport 16448 -j NOTRACK
// iptables -A OUTPUT -t raw -p tcp -m tcp --sport 16448 -j NOTRACK
// iptables -A OUTPUT -p tcp --sport 16448 --tcp-flags RST RST -j DROP

/*
 * phy_dev=eth1
 * eip=114.114.114.114
 * tc qdisc add dev ${phy_dev} root handle 10: htb
 * tc filter del dev ${phy_dev} parent 10: protocol ip prio 10 u32 match ip src 200.200.200.200/32 action nat egress 200.200.200.200/32 ${eip}/32
 * tc filter add dev ${phy_dev} parent 10: protocol ip prio 10 u32 match ip src 200.200.200.200/32 action nat egress 200.200.200.200/32 ${eip}/32

 * tc qdisc add dev ${phy_dev} ingress handle ffff
 * tc filter del dev ${phy_dev} parent ffff: protocol ip prio 10 u32 match ip dport 0x4040 0xffff action nat ingress ${eip}/32 200.200.200.200/32
 * tc filter add dev ${phy_dev} parent ffff: protocol ip prio 10 u32 match ip dport 0x4040 0xffff action nat ingress ${eip}/32 200.200.200.200/32
 * tc filter show dev ${phy_dev} parent ffff:
 */

static struct tcphdr TUNNEL_PADDIND_DNS = {
	.th_sport = 16448,
	.th_dport = 16448,
	.th_win = 0xffff,
	.th_flags = TH_ACK,
	.th_off   = 5
};

#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

static int _tcp_una = 0;
static int _tcp_nxt = 0x100;
static int _tcp_max = 0x100;
static int _tcp_flags = TH_SYN;

static int _tcp_last_sum = 0;
static in_addr_t _tcp_last_peer = 0;
static in_addr_t _tcp_last_name = 0;

static int tcp_low_link_create(void)
{
	int error;
	int bufsiz, devfd, flags;

	devfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	LOG_DEBUG("TCP created: %d\n", devfd);

	bufsiz = 384 * 1024;
	setsockopt(devfd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsiz, sizeof(bufsiz));
	setsockopt(devfd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsiz, sizeof(bufsiz));

	setblockopt(devfd, 0);
	return devfd;
}

static int tcp_low_link_recv_data(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len)
{
	unsigned short key = 0x5aa5;
	char _plain_stream[MAX_PACKET_SIZE], *packet;

	int count = recvfrom(devfd, _plain_stream, sizeof(_plain_stream), MSG_DONTWAIT, ll_addr, ll_len);

	if (count <= 0) return count;

	struct tcphdr *phdr = (struct tcphdr *)(_plain_stream + 20);
	if (phdr->th_dport != 16448) {
		static int _connected = 0;
		if (!_connected) {
			LOG_DEBUG("port mot match: %d %d\n", phdr->th_dport, phdr->th_sport);
			_connected = 1;
		
		}
		errno = EAGAIN;
		return -1;
	}

	packet = _plain_stream + (phdr->th_off << 2);
	count -= (phdr->th_off << 2);
	count -= 20;

	if (count <= sizeof(TUNNEL_PADDIND_DNS)) return -1;

	if (ll_addr != NULL) {
		struct sockaddr_in *soinp = (struct sockaddr_in *)ll_addr;
		soinp->sin_port = phdr->th_sport;
	}

	int flags = phdr->th_flags & (TH_SYN| TH_ACK);
	if (flags == TH_SYN) {
		_tcp_flags = TH_SYN| TH_ACK;
		_tcp_nxt = 0x100;
		_tcp_max = 0x100;
		_tcp_una = htonl(phdr->th_seq) + count +1;
	} else if (flags == (TH_SYN|TH_ACK) && _tcp_flags != TH_ACK) {
		_tcp_flags = TH_ACK;
		_tcp_una = htonl(phdr->th_seq) + count +1;
	} else if (SEQ_LT(_tcp_una, htonl(phdr->th_seq) + count)) {
		_tcp_flags = TH_ACK;
		_tcp_una = htonl(phdr->th_seq) + count;
	} else {
		_tcp_flags = TH_ACK;
	}

	LOG_VERBOSE("recv: %ld\n", count + LEN_PADDING_DNS);
	// memcpy(&key, &packet[14], sizeof(key));
	count = MIN(count, len);
	packet_decrypt(htons(key), buf, packet + 20, count);

	return count;
}

static in_addr_t get_local_name(int devfd, const struct sockaddr *ll_addr, size_t ll_len)
{
	int error;
	socklen_t selflen;
	in_addr_t tcp_name = 0;
	struct sockaddr_in self;

	static int check_first = 0;
	if (check_first == 0) {
		check_first = 1;
		selflen = sizeof(self);
		error = getsockname(devfd, (struct sockaddr *)&self, &selflen);
		if (error == 0 && self.sin_addr.s_addr != 0) {
			_tcp_last_name = self.sin_addr.s_addr;
			return _tcp_last_name;
		}
	}

	if (_tcp_last_name != 0) {
		return _tcp_last_name;
	}

	int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpfd == -1) {
		return _tcp_last_name;
	}

	error = connect(udpfd, ll_addr, ll_len);
	if (error != 0) {
		tcp_name = _tcp_last_name;
		assert(0);
		goto disconnect;
	}

	selflen = sizeof(self);
	error = getsockname(udpfd, (struct sockaddr *)&self, &selflen);
	if (error == 0 && self.sin_addr.s_addr != 0) {
		tcp_name = self.sin_addr.s_addr;
	}

disconnect:
	close(udpfd);

	return tcp_name;
}

static int tcp_low_link_send_data(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len)
{
	unsigned short key = 0x5aa5; // rand();
	uint8_t _crypt_stream[MAX_PACKET_SIZE];

	assert (len + sizeof(TUNNEL_PADDIND_DNS) < sizeof(_crypt_stream));
	memcpy(_crypt_stream, &TUNNEL_PADDIND_DNS, sizeof(TUNNEL_PADDIND_DNS));
	// memcpy(_crypt_stream + 14, &key, 2);

	int optlen = 0;
	unsigned char *optp = _crypt_stream + sizeof(TUNNEL_PADDIND_DNS);
	if (_tcp_flags & TH_SYN) {
		optlen  = 4;
		*optp++ = 3;
		*optp++ = 3;
		*optp++ = 7;
		*optp++ = 0;
	}
	packet_encrypt(htons(key), optp, buf, len);

	struct tcphdr *phdr = (struct tcphdr *)_crypt_stream;

	if (_tcp_flags & TH_SYN) {
		_tcp_nxt = 0x100;
		if (_tcp_flags == TH_SYN) _tcp_max = 0x100;
		phdr->th_seq = htonl(_tcp_nxt -1);
	} else {
		phdr->th_seq = htonl(_tcp_nxt);
	}
	phdr->th_ack = htonl(_tcp_una);
	phdr->th_off = (20 + optlen) >> 2;
	phdr->th_flags = _tcp_flags;

	struct sockaddr_in *soinp = (struct sockaddr_in *)ll_addr;
	if (soinp->sin_addr.s_addr != _tcp_last_peer) {
		in_addr_t tracks[2] = {};
		_tcp_last_peer = soinp->sin_addr.s_addr;

		tracks[0] = _tcp_last_peer;
		tracks[1] = get_local_name(devfd, ll_addr, ll_len);
		_tcp_last_sum  = tcpip_checksum(0, tracks, 8, 0);
	}

	phdr->th_dport = soinp->sin_port;
	phdr->th_sum = tcp_checksum(_tcp_last_sum, _crypt_stream, optlen + len + sizeof(TUNNEL_PADDIND_DNS));

	if (SEQ_LT(_tcp_nxt + len, _tcp_max)) {
		_tcp_nxt = _tcp_max;
	} else if (SEQ_LT(_tcp_max, _tcp_nxt)) {
		int tmp = _tcp_max;
		_tcp_max = _tcp_nxt + len;
		_tcp_nxt = tmp;
	} else {
		_tcp_max = _tcp_nxt + len;
		_tcp_nxt = _tcp_nxt + len + len;
	}

	assert (optlen + len + sizeof(TUNNEL_PADDIND_DNS) + 20 <= 1500);
	protect_reset(IPPROTO_TCP, _crypt_stream, len, ll_addr, ll_len);
	return sendto(devfd, _crypt_stream, optlen + len + sizeof(TUNNEL_PADDIND_DNS), 0, ll_addr, ll_len);
}

static int tcp_low_link_adjust(void)
{
	/* sizeof(struct tcphdr) == 20 */
	return LEN_PADDING_DNS + 4;
}

struct low_link_ops tcp_ops = {
	.create = tcp_low_link_create,
	.get_adjust = tcp_low_link_adjust,
	.send_data = tcp_low_link_send_data,
	.recv_data = tcp_low_link_recv_data
};

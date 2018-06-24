/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TCP Support with SACK for file transfer.
 *
 * Copyright 2017 Duncan Hare, All rights reserved.
 */

#define TCP_ACTIVITY 127		/* Number of packets received   */
					/* before console progress mark */

struct ip_tcp_hdr {
	u8		ip_hl_v;	/* header length and version	*/
	u8		ip_tos;		/* type of service		*/
	u16		ip_len;		/* total length			*/
	u16		ip_id;		/* identification		*/
	u16		ip_off;		/* fragment offset field	*/
	u8		ip_ttl;		/* time to live			*/
	u8		ip_p;		/* protocol			*/
	u16		ip_sum;		/* checksum			*/
	struct in_addr	ip_src;		/* Source IP address		*/
	struct in_addr	ip_dst;		/* Destination IP address	*/
	u16		tcp_src;	/* TCP source port		*/
	u16		tcp_dst;	/* TCP destination port		*/
	u32		tcp_seq;	/* TCP sequence number		*/
	u32		tcp_ack;	/* TCP Acknowledgment number	*/
	u8		tcp_hlen;	/* 4 bits TCP header Length/4	*/
					/* 4 bits Reserved		*/
					/* 2 more bits reserved		*/
	u8		tcp_flags;	/* see defines			*/
	u16		tcp_win;	/* TCP windows size		*/
	u16		tcp_xsum;	/* Checksum			*/
	u16		tcp_ugr;	/* Pointer to urgent data	*/
} __packed;

#define IP_TCP_HDR_SIZE		(sizeof(struct ip_tcp_hdr))
#define TCP_HDR_SIZE		(IP_TCP_HDR_SIZE  - IP_HDR_SIZE)

#define TCP_DATA	0x00	/* Data Packet - internal use only	*/
#define TCP_FIN		0x01	/* Finish flag				*/
#define TCP_SYN		0x02	/* Synch (start) flag			*/
#define TCP_RST		0x04	/* reset flag				*/
#define TCP_PUSH	0x08	/* Push - Notify app			*/
#define TCP_ACK		0x10	/* Acknowledgment of data received	*/
#define TCP_URG		0x20	/* Urgent				*/
#define TCP_ECE		0x40	/* Congestion control			*/
#define TCP_CWR		0x80	/* Congestion Control			*/

/*
 * TCP header options, Seq, MSS, and SACK
 */

#define TCP_SACK 32			/* Number of packets analyzed   */
					/* on leading edge of stream    */

#define TCP_O_END	0x00		/* End of option list		*/
#define TCP_1_NOP	0x01		/* Single padding NOP		*/
#define TCP_O_NOP	0x01010101	/* NOPs pad to 32 bit boundary	*/
#define TCP_O_MSS	0x02		/* MSS Size option		*/
#define TCP_O_SCL	0x03		/* Window Scale option		*/
#define TCP_P_SACK	0x04		/* SACK permitted		*/
#define TCP_V_SACK	0x05		/* SACK values			*/
#define TCP_O_TS	0x08		/* Timestamp option		*/
#define TCP_OPT_LEN_2	0x02
#define TCP_OPT_LEN_3	0x03
#define TCP_OPT_LEN_4	0x04
#define TCP_OPT_LEN_6	0x06
#define TCP_OPT_LEN_8	0x08
#define TCP_OPT_LEN_A	0x0a		/* Timestamp Length		*/

/*
 * Please review the warning in net.c about these two parameters.
 * They are part of a promise of RX buffer size to the sending TCP
 */

#define TCP_MSS		1460		/* Max segment size		*/
#define TCP_SCALE	0x01		/* Scale			*/

struct tcp_mss {			/* TCP Max Segment size		*/
	u8	kind;			/* Field ID			*/
	u8	len;			/* Field length			*/
	u16	mss;			/* Segment size value		*/
} __packed;

struct tcp_scale {			/* TCP Windows Scale		*/
	u8	kind;			/* Field ID			*/
	u8	len;			/* Filed length			*/
	u8	scale;			/* windows shift value used for */
					/* networks with many hops	*/
					/* Typically 4 or more hops	*/

} __packed;

struct tcp_sack_p {			/* SACK permitted		*/
	u8	kind;			/* Field Id			*/
	u8	len;			/* Field length			*/
} __packed;

					/* Terse definitions used       */
					/* long definitions make the    */
					/* indented code overflow line  */
					/* length linits                */
struct sack_edges {
	u32	l;			/* Left edge of stream		*/
	u32	r;			/* right edge of stream		*/
} __packed;

#define TCP_SACK_SIZE (sizeof(struct sack_edges))

/*
 * A TCP stream has holes when packets are missing or disordered.
 * A hill is the inverese of a hole, and is data received.
 * TCP receiveds hills (a sequence of data), and inferrs Holes
 * from the "hills" or packets received.
 */

#define TCP_SACK_HILLS	4

struct tcp_sack_v {
	u8	kind;			/* Field ID		        */
	u8	len;			/* Field Length			*/
	struct	sack_edges hill[TCP_SACK_HILLS]; /* L & R window edges	*/
} __packed;

struct tcp_t_opt {			/* TCP time stamps option	*/
	u8	kind;			/* Field id			*/
	u8	len;			/* Field length			*/
	u32	t_snd;			/* Sender timestamp		*/
	u32	t_rcv;			/* Receiver timestamp		*/
} __packed;

#define TCP_TSOPT_SIZE (sizeof(struct tcp_t_opt))

/*
 * ip tcp  structure with options
 */

struct ip_tcp_hdr_o {
	struct	ip_tcp_hdr hdr;
	struct	tcp_mss	   mss;
	struct	tcp_scale  scale;
	struct	tcp_sack_p sack_p;
	struct	tcp_t_opt  t_opt;
	u8	end;
} __packed;

#define IP_TCP_O_SIZE (sizeof(struct ip_tcp_hdr_o))

struct ip_tcp_hdr_s {
	struct	ip_tcp_hdr	hdr;
	struct	tcp_t_opt	t_opt;
	struct	tcp_sack_v	sack_v;
	u8	end;
} __packed;

#define IP_TCP_SACK_SIZE (sizeof(struct ip_tcp_hdr_s))

/*
 * TCP pseudo header definitions
 */
#define PSEUDO_PAD_SIZE	8

struct pseudo_hdr {
	u8 padding[PSEUDO_PAD_SIZE];	/* pseudo hdr size = ip_tcp hdr size */
	struct in_addr p_src;
	struct in_addr p_dst;
	u8      rsvd;
	u8      p;
	u16     len;
} __packed;

#define PSEUDO_HDR_SIZE	(sizeof(struct pseudo_hdr)) - PSEUDO_PAD_SIZE

/*
 * union for building TCP/IP packet. Build Pseudo header in packed buffer
 * first, calculate TCP checksum, then build IP header in packed buffer.
 */

union tcp_build_pkt {
	struct pseudo_hdr ph;
	struct ip_tcp_hdr_o ip;
	struct ip_tcp_hdr_s sack;
	uchar  raw[1600];
} __packed;

/*
 * TCP State machine states for connection
 */

enum TCP_STATE {
	TCP_CLOSED,		/* Need to send SYN to connect		  */
	TCP_SYN_SENT,		/* Trying to connect, waiting for SYN ACK */
	TCP_ESTABLISHED,	/* both server & client have a connection */
	TCP_CLOSE_WAIT,		/* Rec FIN, passed to app for FIN, ACK rsp*/
	TCP_CLOSING,		/* Rec FIN, sent FIN, ACK waiting for ACK */
	TCP_FIN_WAIT_1,		/* Sent FIN waiting for response	  */
	TCP_FIN_WAIT_2		/* Rec ACK from FIN sent, waiting for FIN */
};

enum TCP_STATE tcp_get_tcp_state(void);
void tcp_set_tcp_state(enum TCP_STATE new_state);
int tcp_set_tcp_header(uchar *pkt, int dport, int sport, int payload_len,
		       u8 action, u32 tcp_seq_num, u32 tcp_ack_num);

/*
 * An incoming packet handler.
 * @param pkt    pointer to the application packet
 * @param dport  destination UDP port
 * @param sip    source IP address
 * @param sport  source UDP port
 * @param len    packet length
 */
typedef void rxhand_tcp(uchar *pkt, unsigned int dport,
			struct in_addr sip, unsigned int sport,
			unsigned int len);
void tcp_set_tcp_handler(rxhand_tcp *f);

void rxhand_tcp_f(union tcp_build_pkt *b, unsigned int len);

/*
 * An incoming TCP packet handler for the TCP protocol.
 * There is also a dynamic function pointer for TCP based commands to
 * receive incoming traffic after the TCP protocol code has done its work.
 */

void rxhand_action(u8 tcp_action, int payload_len, u32 tcp_seq_num,
		   u32 tcp_ack_num, unsigned int pkt_len,
		   union tcp_build_pkt *b);

// copy from  include/uapi/linux/tcp.h of mptcp socket API repo

#ifndef __MPTCP_API_H
#define __MPTCP_API_H

/* MPTCP API */

#define MPTCP_GET_SUB_IDS       66      /* Get subflows ids */
#define MPTCP_CLOSE_SUB_ID      67      /* Close sub id */
#define MPTCP_GET_SUB_TUPLE     68      /* Get sub tuple */
#define MPTCP_OPEN_SUB_TUPLE    69      /* Open sub tuple */
#define MPTCP_GET_SUB_INFO      70      /* Get sub info */

#define MPTCP_SUB_GETSOCKOPT    71      /* Get sockopt for a specific sub */
#define MPTCP_SUB_SETSOCKOPT    72      /* Set sockopt for a specific sub */

/* MPTCP API : cmsg */

#define MPTCP_EV_INIT_SUB       1       /* New subflow init */
#define MPTCP_EV_DEL_SUB        2       /* Subflow deleted */


struct mptcp_sub_setsockopt {
    uint8_t         id;
    int             level;
    int             optname;
    //char __user    *optval;
    char            *optval;
    unsigned int    optlen;
};

struct mptcp_sub_getsockopt {
    uint8_t         id;
    int             level;
    int             optname;
    //char __user    *optval;
    //unsigned int    __user *optlen;
    char            *optval;
    unsigned int    *optlen;
};


struct mptcp_sub_status {
    uint8_t     id;
    uint16_t    slave_sk:1,
                fully_established:1,
                attached:1,
                low_prio:1,
                pre_established:1;
};

struct mptcp_sub_ids {
    uint8_t                  sub_count;
    struct mptcp_sub_status  sub_status[];
};


struct mptcp_close_sub_id {
    uint8_t     id;
};

struct mptcp_sub_tuple {
    uint8_t     id;
//  uint8_t     prio;	// This one in RFC but not implemented yet.
    uint8_t     addrs[0];
};
#endif

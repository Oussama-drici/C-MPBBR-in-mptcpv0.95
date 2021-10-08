#C-MPBBR in v0.95 
This code is for the adapation of C-MPBBR in the new version of mptcp V0.95
In order to compile the code of C-MPBBR in the last MPTCP kernel MPTCP v0.95.1 we
did the following adjustments in the code C that was developed in the previous MPTCP
v0.93.0 https://github.com/imtiaztee/C-MPBBR:

Line 66:

    struct skb_mstamp cycle_mstamp 
    
==> 
    
    u64 cycle_mstamp;

Line 254,255: size of segments

	min_segs = sk->sk_pacing_rate < (mpbbr_min_tso_rate >> 3) ? 1 : 2;
	mpbbr->tso_segs_goal = min(tcp_tso_autosize(sk, tp->mss_cache, min_segs),0x7FU);

==>
    
	bytes = min_t(u32, sk->sk_pacing_rate >> sk->sk_pacing_shift,GSO_MAX_SIZE - 1 - MAX_TCP_HEADER);
	segs = max_t(u32, bytes / tp->mss_cache, (sk->sk_pacing_rate) < (mpbbr_min_tso_rate >> 3) ? 1 : 2);
	mpbbr->tso_segs_goal = min(segs,0x7FU);

Line 366,446: Boucle for the sub flows in the MPTCP
    
    struct sock *sub_sk;			   
    mptcp_for_each_sk(mpcb, sub_sk)

==> 

    struct mptcp_tcp_sock *mptcp;
    mptcp_for_each_sub(mpcb, mptcp)

     
    
    
Line 595: the difference in time
    
    skb_mstamp_us_delta 
    
==> 
    
    tcp_stamp_us_delta

Line 681: Function of transforming the time to us.
    
    mpbbr->lt_last_stamp = tp->delivered_mstamp.stamp_jiffies 
    
==>  	
    
    mpbbr->lt_last_stamp =div_u64(tp->delivered_mstamp, USEC_PER_MSEC);

Line 787: The time of delivering the packets to calculated delivery rate
    
    t = (s32) (tp->delivered_mstamp.stamp_jiffies - mpbbr->lt_last_stamp)  
    
==> 
    
    t = (s32)( div_u64(tp->delivered_mstamp, USEC_PER_MSEC) - mpbbr->lt_last_stamp);

Also the function mpbbr_get_info() is ignored because we does not need the information of the variables utilized in C-MPBBR and it’s replace by 0 value.


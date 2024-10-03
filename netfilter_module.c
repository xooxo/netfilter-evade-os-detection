#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
//#include <uapi/linux/tcp.h>
#include <linux/netdevice.h>

static struct nf_hook_ops nfho;
static char my_buf[64]; // taken from: https://github.com/liaotianyu/myhook_add_tcp_option
static char option_tm[8] = {0xfd, 0x08, 0x03, 0x48, 0x5a, 0x5a, 0x5a, 0x5a};   //the tcp option that will be appended on tcp header


// PoC is to imitate Windows
unsigned int modify_packet(void *priv,
                           struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct  net_device	*dev    ;
    char                    *name   ;
    int                     hdr_len ;
    char                    *d      ;
    int                     i       ;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *) skb_transport_header(skb);//tcp_hdr(skb);
	// idk if I need below:
	// taken from: https://github.com/liaotianyu/myhook_add_tcp_option
	dev     = skb->dev;
	name    = dev->name; //&dev->name;

        // Modify TTL
        iph->ttl = 128;

        // Modify TCP window size
        tcph->window = htons(65535);

	// adding tcp options
	// taken from: https://github.com/liaotianyu/myhook_add_tcp_option
	if( skb->data[0]==0x45 && iph->protocol==0x06 ) {  //ipv4 and tcp packet
		hdr_len = (iph->ihl + tcph->doff)*4;    //original header length, ip header + tcp header
		memcpy(my_buf, skb->data, 64 );	        //copy original header to tmp buf; copy 64B to tmp buf; 64B is bigger than hdr_len;
		memcpy(my_buf+hdr_len, option_tm, 8);   //append new tcp option on original header to generate a new header;
		d = my_buf;
		/*
		for(i=0; i<(hdr_len+8); i++) {          //print the new header
			printk("%02x", (*d)&0xff);
			d++;
		}
		*/
	skb_pull( skb, hdr_len );               //remove original header
        skb_push( skb, hdr_len+8 );             //add new header
        memcpy(skb->data, my_buf, hdr_len+8 );	//copy new header into skb;
	skb->transport_header = skb->transport_header -8;
	skb->network_header   = skb->network_header   -8;
        iph = ip_hdr(skb);  //update iph point to new ip header
        iph->tot_len = htons(skb->len);
        iph->check = 0;     //re-calculate ip checksum
        iph->check = ip_fast_csum( iph, iph->ihl);
        tcph =  (struct tcphdr *) skb_transport_header(skb); //update tcph point to new tcp header
        printk(KERN_INFO"old tcp_checksum=%x \n", tcph->check );
        tcph->doff = tcph->doff+2;
        tcph->check = 0;
        int datalen;
        datalen = (skb->len - iph->ihl*4);  //tcp segment length

	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
    			                datalen, iph->protocol,
    			                csum_partial((char *)tcph, datalen, 0));
        skb->ip_summed = CHECKSUM_UNNECESSARY;  //the reason is not clear, but without it, it seems the hardware will re-calcuate the checksum
}

    }

    return NF_ACCEPT;
}

static int __init init_mod(void)
{
    nfho.hook = modify_packet;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net,&nfho);
    printk(KERN_INFO "Netfilter module loaded.\n");
    return 0;
}

static void __exit cleanup_mod(void)
{
    nf_unregister_net_hook(&init_net,&nfho);
    printk(KERN_INFO "Netfilter module unloaded.\n");
}

module_init(init_mod);
module_exit(cleanup_mod);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GentleVandal");
MODULE_DESCRIPTION("Netfilter Kernel Module for Nmap OS detection evasion.");
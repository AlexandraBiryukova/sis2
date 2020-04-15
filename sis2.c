#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Savoskin Roman, Biryukova Alexandra, Amambayeva Meruert");
MODULE_DESCRIPTION("SIS2: Linux kernel module program to capture all network packets");

struct packet_type packet;
static struct timespec t;
static struct nf_hook_ops *nfho = NULL;
static struct iphdr *iph;
char source[16], dest[16];

void print_addresses(void){
    snprintf(source, 16, "%pI4", &iph->saddr);
    snprintf(dest, 16, "%pI4", &iph->daddr);
    printk("@RAM ID: %d\n", iph->id);
    printk("@RAM SOURCE: %s\n", source);
    printk("@RAM DESTINATION: %s\n", dest);
}

void print_time(void) {
    getnstimeofday(&t);
	printk("@RAM TIME: %.2lu:%.2lu:%2lu\n",
                   (t.tv_sec / 3600 + 6) % (24),
                   (t.tv_sec / 60) % (60),
                    t.tv_sec % 60);
}

int recieve_packet (struct sk_buff *skb, struct net_device *dev, 
                    struct packet_type *pt, struct net_device *orig_dev) {
    printk("\n\n------------------NEW PACKET RECIEVED------------------");
    print_time();
    switch (skb->pkt_type) {
    case PACKET_HOST: printk(KERN_INFO "@RAM TYPE: to us"); break;
    case PACKET_BROADCAST: printk(KERN_INFO "@RAM TYPE: to all"); break;
    case PACKET_MULTICAST: printk(KERN_INFO "@RAM TYPE: to group"); break;
    case PACKET_OTHERHOST: printk(KERN_INFO "@RAM TYPE: to someone else"); break;
    case PACKET_OUTGOING: printk(KERN_INFO "@RAM TYPE: outgoing"); break;
    case PACKET_LOOPBACK: printk(KERN_INFO "@RAM TYPE: LOOPBACK"); break;
    case PACKET_FASTROUTE: printk(KERN_INFO "@RAM TYPE: FASTROUTE"); break;
    case PACKET_KERNEL: printk(KERN_INFO "@RAM TYPE: to kernel space"); break;
    }
    iph = ip_hdr(skb);
    print_addresses();
    // printk(KERN_CONT " Device: %s ; 0x%.4X ; 0x%.4X \n", skb->dev->name, 
    //               ntohs(skb->protocol), ip_hdr(skb)->protocol);
    kfree_skb (skb);
    return 0;
}


static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct udphdr *udph;
	if (!skb) { 
        return NF_ACCEPT; 
    }
    printk("\n\n------------------PACKET IS FILTERED------------------");
	iph = ip_hdr(skb);
    print_addresses();
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (ntohs(udph->dest) == 53) {
            printk(KERN_INFO "@RAM UDP REJECTED");
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
        printk(KERN_INFO "@RAM TCP ACCEPTED");
		return NF_ACCEPT;
	}
    printk(KERN_INFO "@RAM DROPPED");
	return NF_DROP;
}

static int __init ram_init(void) {
    packet.type = htons(ETH_P_IP);
    packet.dev = dev_get_by_name (&init_net, "enp0s3");
    packet.func = recieve_packet;
    dev_add_pack (&packet);
    printk(KERN_INFO "@RAM Module insertion completed successfully!\n");

    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    nfho->hook = (nf_hookfn*)hfunc;
    nfho->hooknum = NF_INET_PRE_ROUTING;
    nfho->pf = PF_INET;
    nfho->priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, nfho);

    return 0;
}

static void __exit ram_cleanup(void) {
    dev_remove_pack(&packet);

    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);

    printk(KERN_INFO "@RAM Cleaning up module....\n");

}

module_init(ram_init);
module_exit(ram_cleanup);

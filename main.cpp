
#include "all.hpp"

const string dname = "vboxnet0";
pcap_t * handle = NULL;
bpf_program bpf = { 0, NULL };
vector<unsigned> vlans;

void cb(u_char * user, const pcap_pkthdr * header, const u_char * data);
void finish(int notused);
void bpf_compile();
void bpf_print();

int main()
{
	int ret = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	try
	{
		throw_if(signal(SIGINT, & finish) == SIG_ERR);
		throw_null(handle = pcap_create(dname.c_str(), errbuf));
		throw_if(pcap_set_promisc(handle, 1));
		throw_if(pcap_activate(handle));
		throw_if(pcap_datalink(handle) != DLT_EN10MB);

		bpf_compile();
		throw_if(pcap_setfilter(handle, & bpf));

		throw_if(pcap_loop(handle, -1, & cb, NULL) == -1);
	}
	catch(...)
	{
		ret = -1;

		if(handle)
			pcap_perror(handle, "Error in libpcap: ");
	}

	if(handle)
		pcap_close(handle);

	if(bpf.bf_insns)
		free(bpf.bf_insns);

	return ret;
}

void finish(int notused)
{
	pcap_breakloop(handle);
}

void cb(u_char * user, const pcap_pkthdr * header, const u_char * data)
{
	const uint16_t * ptr = (uint16_t *) data;
	const uint16_t vlan = htons(* (uint16_t *) (ptr + 7)) & 0x0FFF;
	const uint16_t proto = htons(* (uint16_t *) (ptr + 8));

	printf("TODO: create vlan %u\n", vlan);
	vlans.push_back(vlan);
	
	bpf_compile();
	throw_if(pcap_setfilter(handle, & bpf));
}

void bpf_compile()
{
	const unsigned vlans_num = vlans.size();
	const unsigned size = bpf.bf_len = 5 + vlans_num;
	unsigned v;
	bpf_insn * ptr;
	
	if(bpf.bf_insns)
		free(bpf.bf_insns);

	throw_null(ptr = bpf.bf_insns = (bpf_insn *) malloc(sizeof(bpf_insn) * size));

	ptr[0].code = 0x30;
	ptr[0].jt = 0;
	ptr[0].jf = 0;
	ptr[0].k = 0xFFFFF030;

	ptr[1].code = 0x15;
	ptr[1].jt = 0;
	ptr[1].jf = size - 3;
	ptr[1].k = 0x1;

	ptr[2].code = 0x30;
	ptr[2].jt = 0;
	ptr[2].jf = 0;
	ptr[2].k = 0xfffff02c;

	for(v = 0; v < vlans_num; v++)
	{
		ptr[v + 3].code = 0x15;
		ptr[v + 3].jt = vlans_num - v;
		ptr[v + 3].jf = 0;
		ptr[v + 3].k = vlans[v];
	}

	ptr[size - 2].code = 0x06;
	ptr[size - 2].jt = 0;
	ptr[size - 2].jf = 0;
	ptr[size - 2].k = -1;

	ptr[size - 1].code = 0x06;
	ptr[size - 1].jt = 0;
	ptr[size - 1].jf = 0;
	ptr[size - 1].k = 0;
}

void bpf_print()
{
	unsigned v;

	for(v = 0; v < bpf.bf_len; v++)
		printf("%u -> 0x%X 0x%X 0x%X 0x%X = %u %u %u %u\n", v,
				bpf.bf_insns[v].code,
				bpf.bf_insns[v].jt,
				bpf.bf_insns[v].jf,
				bpf.bf_insns[v].k,
				bpf.bf_insns[v].code,
				bpf.bf_insns[v].jt,
				bpf.bf_insns[v].jf,
				bpf.bf_insns[v].k);
}


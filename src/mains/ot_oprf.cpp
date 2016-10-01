/*
 * ot_oprf.cpp
 *
 *  Created on: May 20, 2015
 *      Author: mzohner
 */


#include "ot_oprf.h"

int32_t main(int32_t argc, char** argv) {
	ot_oprf(argc, argv);
}

int32_t ot_oprf(int32_t argc, char** argv) {
	uint64_t bytes_sent=0, bytes_received=0, mbfac, num_ots;
	uint32_t nelements=0, elebytelen=16, symsecbits=128, i, j, ntasks=1,
			pnelements, maskbitlen;
	uint16_t port=7766;
	string address="127.0.0.1";
	timeval t_start, t_end;
	vector<CSocket> sockfd(ntasks);
	string infilename, outfilename;
	uint32_t* nelesinbin;
	double epsilon = 1.2;
	CBitVector dummy_in, dummy_out;


	role_type role = (role_type) 0;
	psi_prot protocol;

	mbfac=1024*1024;

	read_ot_oprf_options(&argc, &argv, &role, &infilename, &outfilename, &nelements, &elebytelen, &address, &port, &ntasks);

	crypto crypt(symsecbits, (uint8_t*) const_seed);

	if(role == SERVER) {
		listen(address.c_str(), port, sockfd.data(), ntasks);
	} else {
		for(i = 0; i < ntasks; i++)
			connect(address.c_str(), port, sockfd[i]);
	}

	pnelements = exchange_information(nelements, elebytelen, symsecbits, ntasks, protocol, sockfd[0]);
	cout << "nelements = " << nelements << ", pnelements = " << pnelements << endl;
	maskbitlen = crypt.get_seclvl().statbits + ceil_log2(nelements) + ceil_log2(pnelements);
	num_ots = ((uint64_t) role==SERVER ? pnelements : nelements) * epsilon;

	//TODO: generate nelesinbin from infilename

	gettimeofday(&t_start, NULL);

	cout << "Performing " << num_ots << " on " << elebytelen * 8 << " bit elements" << endl;
	if(role == SERVER) {
		KKOTExtSnd* sender = new KKOTExtSnd(m_nCodeWordBits, elebytelen*8, &crypt, sockfd.data());
		sender->send(num_ots, maskbitlen, &dummy_in, &dummy_out, ntasks, nelesinbin);
		delete sender;
	} else {
		KKOTExtRcv* receiver = new KKOTExtRcv(m_nCodeWordBits, elebytelen*8, &crypt, sockfd.data());
		receiver->receive(num_ots, maskbitlen, &dummy_in, &dummy_out, ntasks, nelesinbin);
		delete receiver;
	}
	cout << "OTs done." << endl;

	gettimeofday(&t_end, NULL);

	for(i = 0; i < sockfd.size(); i++) {
		bytes_sent += sockfd[i].get_bytes_sent();
		bytes_received += sockfd[i].get_bytes_received();
	}

	cout << "Required time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end)/1000 << " s" << endl;
	cout << "Data sent:\t" <<	((double)bytes_sent)/mbfac << " MB" << endl;
	cout << "Data received:\t" << ((double)bytes_received)/mbfac << " MB" << endl;

	return 1;
}




int32_t read_ot_oprf_options(int32_t* argcp, char*** argvp, role_type* role, string* infilename,
		string* outfilename, uint32_t* nelements, uint32_t* bytelen, string* address, uint16_t* port, uint32_t* nthreads) {

	uint32_t int_role, int_protocol = 0, int_port = 0;
	parsing_ctx options[] = {{(void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false},
			{(void*) infilename, T_STR, 'f', "Input file", true, false},
			{(void*) outfilename, T_STR, 'o', "Output file", true, false},
			{(void*) nelements, T_NUM, 'n', "Number of elements", true, false},
			{(void*) bytelen, T_NUM, 'b', "Byte length of elements", true, false},
			{(void*) address, T_STR, 'a', "Server IP-address (needed by both, client and server)", false, false},
			{(void*) &int_port, T_NUM, 'p', "Port", false, false},
			{(void*) nthreads, T_NUM, 't', "Number of threads", false, false}
	};

	if(!parse_options(argcp, argvp, options, sizeof(options)/sizeof(parsing_ctx))) {
		print_usage(argvp[0][0], options, sizeof(options)/sizeof(parsing_ctx));
		exit(0);
	}

	assert(int_port < 65536);
	if(int_port != 0)
		*port = (uint16_t) int_port;

	assert(int_role < 2);
	*role = (role_type) int_role;

	return 1;
}

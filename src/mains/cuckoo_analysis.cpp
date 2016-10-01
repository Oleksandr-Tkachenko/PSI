/*
 * cuckoo_analysis.cpp
 *
 *  Created on: Nov 10, 2014
 *      Author: mzohner
 */

#include "cuckoo_analysis.h"


int32_t main(int32_t argc, char** argv) {
	analyze_hashing(argc, argv);
}

int32_t analyze_hashing(int32_t argc, char** argv) {
	double epsilon=1.2;
	uint32_t rndbytes, neles, elebitlen=16, nbins, ntasks=1, outbitlen, nruns=1;
	uint32_t *nelesinbin, *perm;
	uint8_t *elements;
	bool use_simple_hashing=false;
	timeval t_start;
	prf_state_ctx prf_state;
	crypto *crypt, *cryptB;// = new crypto(128);
	CBitVector sampled;
	uint8_t* seed = (uint8_t*) malloc(AES_BYTES);
	memcpy(seed, const_seed, AES_BYTES);

	gettimeofday(&t_start, NULL);
	((uint32_t*) seed)[0] += t_start.tv_usec;
	crypt = new crypto(128, (uint8_t*) seed);
	cryptB = new crypto(128, (uint8_t*) seed);

	uint32_t tstnbytes = 262144;
	uint8_t* bufa = (uint8_t*) malloc(tstnbytes);
	uint8_t* bufb = (uint8_t*) malloc(tstnbytes);
	crypt->gen_rnd(bufa, tstnbytes);
	/*cryptB->gen_rnd_pipelined(bufb, tstnbytes);

	for(uint32_t i = 0; i < tstnbytes; i++) {
		assert(bufa[i] == bufb[i]);
	}*/

	//assert(elebitlen <= 32);
	sampled.Create(1L<<elebitlen);

	read_bench_options(&argc, &argv, &neles, &epsilon, &nruns, &use_simple_hashing);

	rndbytes = neles * ceil_divide(elebitlen, 8);
	elements = (uint8_t*) malloc(rndbytes);

#ifdef DOUBLE_TABLE
	nbins = epsilon*(neles);
#else
	#if NUM_HASH_FUNCTIONS == 2
	nbins = 2*epsilon*(neles);
	#else
	nbins = epsilon*neles;
	#endif
#endif

	nelesinbin = (uint32_t*) malloc(sizeof(uint32_t) * nbins);
	perm = (uint32_t*) calloc(neles, sizeof(uint32_t));

	//cryto stuff
	crypt->init_prf_state(&prf_state, (uint8_t*) seed);

#ifndef TEST_CHAINLEN
	cout << "Starting Cuckoo hashing for " << neles << " elements of " << elebitlen << " bit-length"
		<< " and for " << nbins << " bins on " << nruns << " iterations, seed = " << ((uint32_t*) seed)[0] << endl;
#endif

	gen_distinct_rnd_elements(elements, crypt, neles, ceil_divide(elebitlen, 8), &sampled);

	if(use_simple_hashing) {
		analyze_simple_hashing(elements, neles, nbins, elebitlen, outbitlen, nelesinbin, perm, ntasks, nruns, prf_state);
	} else {
		analyze_cuckoo_hashing(elements, neles, nbins, elebitlen, outbitlen, nelesinbin, perm, ntasks, nruns, prf_state);
	}

#ifdef TEST_CHAINLEN
	print_chain_cnt();
#endif


	free(nelesinbin);
	free(perm);
	free(elements);
	return 0;
}


void analyze_simple_hashing(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t elebitlen, uint32_t outbitlen,
		uint32_t* nelesinbin, uint32_t* perm, uint32_t ntasks, uint32_t nruns, prf_state_ctx prf_state) {
	uint32_t maxbinsize;
	vector<uint32_t> maxbinsize_cnt(1,0);
	timeval t_start, t_end;

	gettimeofday(&t_start, NULL);

	for(uint32_t i = 0; i < nruns; i++) {
#ifdef TEST_UTILIZATION
		maxbinsize = simple_hashing(elements, neles, elebitlen, &outbitlen,
			nelesinbin, nbins, ntasks, &prf_state);
#else
		cerr << "Test utilization not active, will not work. Exiting!" << endl;
		exit(0);
#endif
		update_maxbinsizes(maxbinsize, maxbinsize_cnt);
		notify_maxbin(i, maxbinsize_cnt, t_start);
	}

	gettimeofday(&t_end, NULL);
	cout << "Time needed for " << nruns  << " iterations: " << getMillies(t_start, t_end)/1000 << " s" << endl;
	cout << "Allocation: " << endl;

	for(uint32_t i = 0; i < maxbinsize_cnt.size(); i++) {
		if(maxbinsize_cnt[i] > 0)
			cout << i << ": " << maxbinsize_cnt[i] << endl;
	}
	maxbinsize_cnt.clear();
}

inline void update_maxbinsizes(uint32_t maxbinsize, vector<uint32_t>& maxbinsize_cnt) {
	if(maxbinsize >= maxbinsize_cnt.size()) {
		maxbinsize_cnt.resize(maxbinsize+1, 0);
	}
	maxbinsize_cnt[maxbinsize]++;
}

inline void notify_maxbin(uint32_t nrun, vector<uint32_t> maxbins, timeval t_start) {
	if(popcount_3(nrun) == 1) {
		timeval t_end;
		gettimeofday(&t_end, NULL);

		cout << "Time needed for " << nrun  << " iterations: " << getMillies(t_start, t_end)/1000 << " s" << endl;
		cout << "Allocation: " << endl;
		for(uint32_t i = 0; i < maxbins.size(); i++) {
			if(maxbins[i] > 0)
				cout << "max bin size " << i << ": " << maxbins[i] << endl;
		}
	}
}


void analyze_cuckoo_hashing(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t elebitlen, uint32_t outbitlen,
		uint32_t* nelesinbin, uint32_t* perm, uint32_t ntasks, uint32_t nruns, prf_state_ctx prf_state) {
	uint32_t maxstashsize=10, stashsize;
	uint32_t* stashalloc = (uint32_t*) calloc(maxstashsize, sizeof(uint32_t));
	timeval t_start, t_end;

	gettimeofday(&t_start, NULL);

	for(uint32_t i = 0; i < nruns; i++) {
#ifdef TEST_UTILIZATION
		stashsize = cuckoo_hashing(elements, neles, nbins, elebitlen, &outbitlen,
			nelesinbin, perm, ntasks, &prf_state);
		update_stashalloc(maxstashsize, stashsize, &stashalloc);
#endif
		notify(i, stashalloc, t_start, maxstashsize);
	}

	gettimeofday(&t_end, NULL);
	cout << "Time needed for " << nruns  << " iterations: " << getMillies(t_start, t_end)/1000 << " s" << endl;
	cout << "Allocation: " << endl;
	for(uint32_t i = 0; i < maxstashsize; i++) {
		cout << i << ": " << stashalloc[i] << endl;
	}
	free(stashalloc);
}

inline void update_stashalloc(uint32_t maxstashsize, uint32_t stashsize, uint32_t** stashalloc) {
	uint32_t* tmpstashalloc;
	if(stashsize > maxstashsize) {
		tmpstashalloc = *stashalloc;
		(*stashalloc) = (uint32_t*) calloc((stashsize+1), sizeof(uint32_t));
		memcpy(*stashalloc, tmpstashalloc, maxstashsize * sizeof(uint32_t));
		free(tmpstashalloc);
		maxstashsize = stashsize+1;
	}
	(*stashalloc)[stashsize]++;
}

inline void notify(uint32_t nrun, uint32_t* stashalloc, timeval t_start, uint32_t maxstashsize) {
	if(popcount_3(nrun) == 1) {
		timeval t_end;
		gettimeofday(&t_end, NULL);

		cout << "Time needed for " << nrun  << " iterations: " << getMillies(t_start, t_end)/1000 << " s" << endl;
		cout << "Allocation: " << endl;
		for(uint32_t i = 0; i < maxstashsize; i++) {
			cout << "stash size " << i << ": " << stashalloc[i] << endl;
		}
	}
}

int32_t read_bench_options(int32_t* argcp, char*** argvp, uint32_t* nelements, double* epsilon,
		uint32_t* nruns, bool* simple_hashing) {


	parsing_ctx options[] = {{(void*) nelements, T_NUM, 'n', "Num elements", true, false},
			{(void*) epsilon, T_DOUBLE, 'e', "Epsilon in Cuckoo hashing", false, false},
			{(void*) nruns, T_NUM, 'r', "Number of repetitions", true, false},
			{(void*) simple_hashing, T_FLAG, 's', "Analyze simple hashing", false, false},
	};

	if(!parse_options(argcp, argvp, options, sizeof(options)/sizeof(parsing_ctx))) {
		print_usage(argvp[0][0], options, sizeof(options)/sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	return 1;
}

/* Code from http://en.wikipedia.org/wiki/Hamming_weight */
//This uses fewer arithmetic operations than any other known
//implementation on machines with fast multiplication.
//It uses 12 arithmetic operations, one of which is a multiply.
int popcount_3(uint64_t x) {
    x -= (x >> 1) & m1;             //put count of each 2 bits into those 2 bits
    x = (x & m2) + ((x >> 2) & m2); //put count of each 4 bits into those 4 bits
    x = (x + (x >> 4)) & m4;        //put count of each 8 bits into those 8 bits
    return (x * h01)>>56;  //returns left 8 bits of x + (x<<8) + (x<<16) + (x<<24) + ...
}

inline void gen_distinct_rnd_elements(uint8_t* elements, crypto* crypt, uint32_t neles,
		uint32_t elebytelen, CBitVector* sampled) {
	uint64_t mask, addr = 0;
	uint8_t* eleptr;

	crypt->gen_rnd(elements, neles * elebytelen);

	memset(&mask, 0xFF, elebytelen);

	eleptr = elements;
	for(uint32_t i = 0; i < neles; i++, eleptr+=elebytelen) {
		memcpy(&addr, eleptr, elebytelen);
		while(sampled->GetBit(addr)) {
			crypt->gen_rnd(eleptr, elebytelen);
			memcpy(&addr, eleptr, elebytelen);
		}
		sampled->SetBit(addr, 1);
	}
}

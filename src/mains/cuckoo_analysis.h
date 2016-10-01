/*
 * cuckoo_analysis.h
 *
 *  Created on: Nov 10, 2014
 *      Author: mzohner
 */

#ifndef CUCKOO_ANALYSIS_H_
#define CUCKOO_ANALYSIS_H_


#include <fstream>
#include <iostream>
#include <string>
#include "../util/parse_options.h"
#include "../hashing/cuckoo.h"
#include "../hashing/simple_hashing.h"
#include "../util/cbitvector.h"
#include "../hashing/hashing_util.h"

/* Needed for efficient HW computation */
const uint64_t m1  = 0x5555555555555555; //binary: 0101...
const uint64_t m2  = 0x3333333333333333; //binary: 00110011..
const uint64_t m4  = 0x0f0f0f0f0f0f0f0f; //binary:  4 zeros,  4 ones ...
const uint64_t h01 = 0x0101010101010101; //the sum of 256 to the power of 0,1,2,3...

using namespace std;

//#define PRINT_INPUT_ELEMENTS
//#define PRINT_INTERSECTION



int32_t analyze_hashing(int32_t argc, char** argv);
inline void gen_distinct_rnd_elements(uint8_t* elements, crypto* crypt, uint32_t neles,
		uint32_t elebytelen, CBitVector* sampled);

void analyze_simple_hashing(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t elebitlen, uint32_t outbitlen,
		uint32_t* nelesinbin, uint32_t* perm, uint32_t ntasks, uint32_t nruns, prf_state_ctx prf_state);
inline void update_maxbinsizes(uint32_t maxbinsize, vector<uint32_t>& maxbinsize_cnt);
inline void notify_maxbin(uint32_t nrun, vector<uint32_t> maxbins, timeval t_start);

void analyze_cuckoo_hashing(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t elebitlen, uint32_t outbitlen,
		uint32_t* nelesinbin, uint32_t* perm, uint32_t ntasks, uint32_t nruns, prf_state_ctx prf_state);
inline void update_stashalloc(uint32_t maxstashsize, uint32_t stashsize, uint32_t** stashalloc);
inline void notify(uint32_t nrun, uint32_t* stashalloc, timeval t_start, uint32_t maxstashsize);


int popcount_3(uint64_t x);
int32_t read_bench_options(int32_t* argcp, char*** argvp, uint32_t* nelements, double* epsilon, uint32_t* nruns,
		bool* simple_hashing);


#endif /* CUCKOO_ANALYSIS_H_ */

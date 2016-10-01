/*
 * ot_oprf.h
 *
 *  Created on: July 12, 2016
 *      Author: mzohner
 */

#ifndef OT_OPRT_H_
#define OT_OPRT_H_

#include "../util/ot/kk-ot-extension.h"
#include "../util/parse_options.h"
#include "../util/helpers.h"
#include "../util/typedefs.h"
#include "../util/connection.h"
#include <fstream>
#include <iostream>
#include <string>



using namespace std;

//#define PRINT_INPUT_ELEMENTS

int32_t ot_oprf(int32_t argc, char** argv);

int32_t read_ot_oprf_options(int32_t* argcp, char*** argvp, role_type* role, string* infilename,
		string* outfilename, uint32_t* nelements, uint32_t* bytelen, string* address, uint16_t* port,
		uint32_t* nthreads);

#endif /* OT_OPRT_H_ */

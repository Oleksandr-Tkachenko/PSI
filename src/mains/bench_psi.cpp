/*
 * bench_psi.cpp
 *
 *  Created on: Nov 10, 2014
 *      Author: mzohner
 */

#include "bench_psi.h"

int32_t main(int32_t argc, char** argv) {
    benchroutine(argc, argv);
}

int32_t benchroutine(int32_t argc, char** argv) {
    string input_path, output_path;
    uint32_t nelements = 0, elebytelen = 4, symsecbits = 128,
            intersect_size, i, ntasks = 1, runs = 1, j, nclients = 2, pnelements;
    uint8_t *elements, *intersection;
    string address = "127.0.0.1";
    uint16_t port = 7766;
    timeval begin, end;
    vector<CSocket> sockfd;
    field_type ftype = ECC_FIELD;
    role_type role = (role_type) 0;
    uint64_t bytes_sent = 0, bytes_received = 0, mbfac;
    psi_prot protocol;
    double epsilon = 1.2;
    bool cardinality = false;
    bool detailed_timings = false;

    mbfac = 1;

    read_bench_options(&argc, &argv, &role, &input_path, &output_path, &nelements, &elebytelen, &symsecbits,
            &address, &port, &ntasks, &protocol, &nclients, &epsilon, &cardinality, &ftype,
            &detailed_timings, &runs);
    sockfd.resize(ntasks);
    if (role == SERVER) {
        if (protocol == TTP) {
            ntasks = nclients;
            sockfd.resize(ntasks);
        }
        listen(address.c_str(), port, sockfd.data(), ntasks);
    } else {
        for (i = 0; i < ntasks; i++)
            connect(address.c_str(), port, sockfd[i]);
    }

    crypto crypto(symsecbits, (uint8_t*) const_seed);

    //exchange number of items, bit-length of items, symmetric security parameter and protocol to make sure the parameters are correct
    if (protocol != TTP) {
        pnelements = exchange_information(nelements, elebytelen, symsecbits, ntasks, protocol, sockfd[0]);
    }

    if (protocol != TTP || role != SERVER) {
        elements = (uint8_t*) calloc(nelements * elebytelen, sizeof (uint8_t));
        crypto.gen_rnd(elements, elebytelen * nelements);
    }

    for (i = 0; i < sockfd.size(); i++) {
        sockfd[i].reset_tracking();
    }

#ifdef PRINT_INPUT_ELEMENTS
    for (i = 0; i < nelements; i++) {
        cout << "Element " << i << ": " << (hex);
        for (j = 0; j < elebytelen; j++)
            cout << (uint32_t) elements[i * elebytelen + j];
        cout << (dec) << endl;
    }
#endif

#ifndef BATCH
    cout << "Benchmarking protocol " << protocol << " on " << runs << " runs" << endl;
#endif
    gettimeofday(&begin, NULL);
    for (i = 0; i < runs; i++) {
        switch (protocol) {
            case NAIVE:
                naivepsi(role, nelements, pnelements, elebytelen, elements, &intersection, &crypto, sockfd.data(), ntasks);
                break;
            case TTP:
                ttppsi(role, nelements, elebytelen, elements, &intersection, &crypto, sockfd.data(), nclients, cardinality);
                break;
            case DH_ECC:
                intersect_size = dhpsi(role, nelements, pnelements, elebytelen, elements, &intersection, &crypto, sockfd.data(),
                        ntasks, cardinality, ftype);
                break;
#ifdef BILLION_SET
            case OT_PSI:
                intersect_size = otpsi(role, &input_path, &output_path, nelements, pnelements, elebytelen, elements, 
                        &intersection, &crypto, sockfd.data(), ntasks, epsilon, detailed_timings);
#else
            case OT_PSI:
                intersect_size = otpsi(role, nelements, pnelements, elebytelen, elements, &intersection, &crypto, sockfd.data(),
                        ntasks, epsilon, detailed_timings);
#endif
                break;
            default:break;
        }
    }
    gettimeofday(&end, NULL);

    for (i = 0; i < sockfd.size(); i++) {
        bytes_sent += sockfd[i].get_bytes_sent();
        bytes_received += sockfd[i].get_bytes_received();
    }
#ifdef BATCH
    cout << getMillies(begin, end) << "\t" << ((double) bytes_sent + bytes_received) / mbfac << endl;


#else
    cout << "Required time per exec:\t" << getMillies(begin, end) / runs << " ms" << endl;
    cout << "Data sent per exec:\t" << (uint64_t) bytes_sent / (mbfac * runs) << " Bytes" << endl;
    cout << "Data received per exec:\t" << (uint64_t) bytes_received / (mbfac * runs) << " Bytes" << endl;
#endif

#ifdef PRINT_INTERSECTION
    cout << "Found " << intersect_size << " intersecting elements" << endl;
    if (!cardinality) {
        for (i = 0; i < intersect_size; i++) {
            for (j = 0; j < elebytelen; j++) {
                cout << (hex) << (uint32_t) intersection[i * elebytelen + j] << (dec);
            }
            cout << endl;
        }
    }
#endif
    if (protocol != TTP || role != SERVER) {
        free(elements);
    }
    return 0;
}

int32_t read_bench_options(int32_t* argcp, char*** argvp, role_type* role, string* input_path, string* output_path,
        uint32_t* nelements, uint32_t* bytelen, uint32_t* secparam, string* address, uint16_t* port,
        uint32_t* ntasks, psi_prot* protocol, uint32_t* nclients, double* epsilon, bool* cardinality,
        field_type* ftype, bool* detailed_timings, uint32_t* nexecs) {

    uint32_t int_role = 0, int_port = 0, int_protocol = 0;
    bool useffc = false;

    parsing_ctx options[] = {
        {(void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false},
        {(void*) &int_protocol, T_NUM, 'p', "PSI protocol (0: Naive, 1: TTP, 2: DH, 3: OT)", true, false},
        {(void*) nelements, T_NUM, 'n', "Number of elements", true, false},
        {(void*) bytelen, T_NUM, 'b', "Byte length of elements", true, false},
        {(void*) secparam, T_NUM, 's', "Symmetric Security Bits (default: 128)", false, false},
        {(void*) address, T_STR, 'a', "Server IP-address (needed by both, client and server)", false, false},
        {(void*) &int_port, T_NUM, 'o', "Port", false, false},
        {(void*) ntasks, T_NUM, 't', "Number of threads", false, false},
        {(void*) nclients, T_NUM, 'c', "Number of clients for TTP based protocol", false, false},
        {(void*) epsilon, T_DOUBLE, 'e', "Epsilon in Cuckoo hashing", false, false},
        {(void*) cardinality, T_FLAG, 'y', "Compute cardinality (only for DH and TTP PSI)", false, false},
        {(void*) &useffc, T_FLAG, 'f', "Use finite-field cryptography", false, false},
        {(void*) detailed_timings, T_FLAG, 'd', "Flag: Enable Detailed Timings", false, false},
        {(void*) nexecs, T_NUM, 'x', "Number of Executions, default 1", false, false},
        {(void*) input_path, T_STR, 'i', "Path to the input file", false, false},
        {(void*) output_path, T_STR, 'u', "Path to the output file", false, false}
    };

    if (!parse_options(argcp, argvp, options, sizeof (options) / sizeof (parsing_ctx))) {
        print_usage(argvp[0][0], options, sizeof (options) / sizeof (parsing_ctx));
        cout << "Exiting" << endl;
        exit(0);
    }

    assert(int_role < 2);
    *role = (role_type) int_role;

    assert(int_protocol < PROT_LAST);
    *protocol = (psi_prot) int_protocol;

    if (int_port != 0) {
        assert(int_port < 1 << (sizeof (uint16_t)*8));
        *port = (uint16_t) int_port;
    }

    if (useffc) {
        *ftype = P_FIELD;
    }

    return 1;
}


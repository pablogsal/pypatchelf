from libcpp.string cimport string

cdef extern from "patchelf_api.h":
    void patchElf(const string filename, const string RPath)


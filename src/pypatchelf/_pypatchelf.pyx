from _pypatchelf.patchelf cimport patchElf

def change_rpath(filename, new_rpath):
    patchElf(filename, new_rpath)

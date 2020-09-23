from distutils.core import setup, Extension
import os
import sys

from Cython.Build import cythonize

install_requires = []

TEST_BUILD = False
if "--test-build" in sys.argv:
    TEST_BUILD = True
    sys.argv.remove("--test-build")


if os.getenv("CYTHON_TEST_MACROS", None) is not None:
    TEST_BUILD = True


COMPILER_DIRECTIVES = {
    "language_level": 3,
    "embedsignature": True,
    "boundscheck": False,
    "wraparound": False,
    "cdivision": True,
    "linetrace": True,
    "c_string_type": "unicode",
    "c_string_encoding": "utf8",
}

DEFINE_MACROS = []

if TEST_BUILD:
    COMPILER_DIRECTIVES = {
        'language_level': 3,
        'boundscheck': True,
        'embedsignature': True,
        'wraparound': True,
        "cdivision": False,
        'profile': True,
        'linetrace': True,
        'overflowcheck': True,
        'infer_types': True,
        "c_string_type": "unicode",
        "c_string_encoding": "utf8",
    }
    DEFINE_MACROS.extend([('CYTHON_TRACE', '1'), ('CYTHON_TRACE_NOGIL', '1')])


PYSTACK_EXTENSION = Extension(
        name="pypatchelf._pypatchelf",
        sources=[
            "src/pypatchelf/_pypatchelf.pyx",
            "src/pypatchelf/_pypatchelf/patchelf.cpp",
        ],
        libraries=[],
        include_dirs=["src"],
        language="c++",
        extra_compile_args=["-std=c++17"],
        extra_link_args=["-std=c++17"],
        define_macros=DEFINE_MACROS,
    )

PYSTACK_EXTENSION.libraries.append("dl")

setup(
    name="pypatchelf",
    version="0.3.2" + os.environ.get("LOCAL_VERSION_LABEL", ""),
    python_requires='>=3.7.0',
    description="Analysis of the stack of remote python processes",
    author="Pablo Galindo Salgado",
    package_dir={"": "src"},
    packages=["pypatchelf"],
    ext_modules=cythonize(
        [PYSTACK_EXTENSION],
        include_path=["src/pypatchelf"],
        compiler_directives=COMPILER_DIRECTIVES,
    ),
    install_requires=install_requires,
)


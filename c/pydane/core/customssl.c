// coding=utf-8
//
// Copyright (C) 2014, Alexandre Vaissière
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/*
 * This module provides some convenience methods for validating X509 certificates.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

/**
 * Sets the python interpreter exception from an error of a
 * failed SSL call. For now, this code sets only RuntimeError.
 */
static void
_set_ssl_error(int lineno)
{
    const char* message;
    PyObject *msg = NULL, *err_value = NULL;
    unsigned long err;

    err = ERR_get_error();
    if (err != 0) {
        message = ERR_error_string(err, NULL);
    }
    else {
        message = "Unknown error.";
    }

    msg = PyUnicode_FromFormat("%s (customssl.c:%d)", message, lineno);
    if (msg == NULL)
        goto clean;

    PyErr_SetObject(PyExc_RuntimeError, msg);

clean:
    Py_XDECREF(err_value);
}

/**
 * Converts a Python bytes list to a STACK_OF(X509) list.
 */
static int
_cert_list_converter(PyObject * list, void* certs)
{
    STACK_OF(X509) *res = NULL;
	X509 * cert = NULL;
	PyObject * py_cert = NULL;
    const unsigned char * der_cert;
    Py_ssize_t cert_number, der_len;
    Py_ssize_t i;

    if (!PyList_Check(list)) {
        goto clean;
    }

    res = sk_X509_new(NULL);
    if (!res) {
        _set_ssl_error(__LINE__);
        goto clean;
    }

    cert_number = PyList_Size(list);
    for (i = 0; i < cert_number; ++i) {
        py_cert = PyList_GetItem(list, i);
        if (!py_cert)
            goto clean;

        if (PyBytes_AsStringAndSize(py_cert, &der_cert, &der_len) == -1)
            goto clean;

        cert = d2i_X509(NULL, &der_cert, der_len);
        if (cert == NULL) {
            _set_ssl_error(__LINE__);
            goto clean;
         }

        sk_X509_push(res, cert);
        cert = NULL;
    }

    goto end;

clean:
    if (res) {
        sk_X509_pop_free(res, X509_free);
        res = NULL;
    }
    if (cert) {
        X509_free(cert);
        cert = NULL;
    }

end:
    *(void**)certs = res;

    return (res == NULL) ? 0 : 1;
}

/**
 * Perform validation of given certificate.
 */
static PyObject *
customssl_validate(PyObject *self, PyObject *args, PyObject *kwds)
{
    char *kwlist[] = { "cert", "cafile", "capath", "extra_certs", NULL };
    unsigned const char* der_cert;
    Py_ssize_t der_len;
    PyObject *py_cafile = NULL, *py_capath = NULL;
    const char *cafile = NULL, *capath = NULL;

	X509* cert = NULL;
	X509_STORE* store = NULL;
	STACK_OF(X509)* extra_certs = NULL;
	X509_STORE_CTX* vrfy_ctx = NULL;

	int sts = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#|O&O&O&", kwlist,
                                     &der_cert, &der_len,
                                     PyUnicode_FSConverter, &py_cafile,
                                     PyUnicode_FSConverter, &py_capath,
                                     _cert_list_converter, &extra_certs))
        return NULL;

    cert = d2i_X509(NULL, &der_cert, der_len);
    if (cert == NULL) {
        _set_ssl_error(__LINE__);
        goto clean;
    }

    if (!(store = X509_STORE_new())) {
        _set_ssl_error(__LINE__);
        goto clean;
    }

    /* load cafile or capath */
    if (py_cafile || py_capath) {
        if (py_cafile)
            cafile = PyBytes_AS_STRING(py_cafile);
        if (py_capath)
            capath = PyBytes_AS_STRING(py_capath);

        if (X509_STORE_load_locations(store, cafile, capath) != 1) {
            _set_ssl_error(__LINE__);
            goto clean;
        }
    }

	if (!(vrfy_ctx = X509_STORE_CTX_new()))
	    goto clean;

    if (X509_STORE_CTX_init(vrfy_ctx, store, cert, extra_certs) != 1)
        goto clean;

    sts = X509_verify_cert(vrfy_ctx);
    if (sts != 1) {
        const char* message;
        unsigned long err =	X509_STORE_CTX_get_error(vrfy_ctx);
        if (err != 0) {
            message = X509_verify_cert_error_string(err);
        }
        else {
            message = "Unknown error.";
        }

        PyErr_SetString(PyExc_RuntimeError, message);
        sts = -1;
    }
    goto clean;

clean:
    Py_XDECREF(py_cafile);
    Py_XDECREF(py_capath);
    if (extra_certs) {
        sk_X509_pop_free(extra_certs, X509_free);
    }
    if (vrfy_ctx) {
    	X509_STORE_CTX_free(vrfy_ctx);
    }
    if (store) {
		X509_STORE_free(store);
	}

    if (sts == -1)
        return NULL;

    return PyLong_FromLong(der_len);
}

static PyMethodDef customssl_methods[] = {
    {"validate", (PyCFunction)customssl_validate, METH_VARARGS | METH_KEYWORDS,
     "Validates the given certificate."},

     {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyDoc_STRVAR(module_doc,
"Provides methods for PKIX-validating certificates using OpenSSL.");

static struct PyModuleDef _customsslmodule = {
    PyModuleDef_HEAD_INIT,
    "pydane.core.customssl",
    module_doc,
    -1,
    customssl_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_customssl(void)
{
    PyObject* m;

    m = PyModule_Create(&_customsslmodule);
    if (m == NULL)
        return NULL;

    SSL_load_error_strings();

    return m;
}

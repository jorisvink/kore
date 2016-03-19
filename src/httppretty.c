/*
 * Copyright (c) 2016 Ángel González <aglezabad@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "httppretty.h"

const char * kore_http_pretty_method(int http_method)
{
    switch(http_method)
    {
        case HTTP_METHOD_GET:
            return "GET";
        case HTTP_METHOD_POST:
            return "POST";
        case HTTP_METHOD_PUT:
            return "PUT";
        case HTTP_METHOD_DELETE:
            return "DELETE";
        case HTTP_METHOD_HEAD:
            return "HEAD";
        default:
            return "ND";
    }
}

const char * kore_http_pretty_codes(int http_codes)
{
    switch(http_codes)
    {
        case HTTP_STATUS_CONTINUE:
            return "Continue";
        case HTTP_STATUS_SWITCHING_PROTOCOLS:
            return "Switching protocols";
        case HTTP_STATUS_OK:
            return "Ok";
        case HTTP_STATUS_CREATED:
            return "Created";
        case HTTP_STATUS_ACCEPTED:
            return "Accepted";
        case HTTP_STATUS_NON_AUTHORITATIVE:
            return "Non authoritative";
        case HTTP_STATUS_NO_CONTENT:
            return "No content";
        case HTTP_STATUS_RESET_CONTENT:
            return "Reset content";
        case HTTP_STATUS_PARTIAL_CONTENT:
            return "Partial content";
        case HTTP_STATUS_MULTIPLE_CHOICES:
            return "Multiple choices";
        case HTTP_STATUS_MOVED_PERMANENTLY:
            return "Moved permanently";
        case HTTP_STATUS_FOUND:
            return "Found";
        case HTTP_STATUS_SEE_OTHER:
            return "See other";
        case HTTP_STATUS_NOT_MODIFIED:
            return "Not modified";
        case HTTP_STATUS_USE_PROXY:
            return "Use proxy";
        case HTTP_STATUS_TEMPORARY_REDIRECT:
            return "Temporary redirect";
        case HTTP_STATUS_BAD_REQUEST:
            return "Bad request";
        case HTTP_STATUS_UNAUTHORIZED:
            return "Unauthorized";
        case HTTP_STATUS_PAYMENT_REQUIRED:
            return "Payment required";
        case HTTP_STATUS_FORBIDDEN:
            return "Forbidden";
        case HTTP_STATUS_NOT_FOUND:
            return "Not found";
        case HTTP_STATUS_METHOD_NOT_ALLOWED:
            return "Not allowed";
        case HTTP_STATUS_NOT_ACCEPTABLE:
            return "Not acceptable";
        case HTTP_STATUS_PROXY_AUTH_REQUIRED:
            return "Proxy auth required";
        case HTTP_STATUS_REQUEST_TIMEOUT:
            return "Request timeout";
        case HTTP_STATUS_CONFLICT:
            return "Conflict";
        case HTTP_STATUS_GONE:
            return "Gone";
        case HTTP_STATUS_LENGTH_REQUIRED:
            return "Length required";
        case HTTP_STATUS_PRECONDITION_FAILED:
            return "Precondition failed";
        case HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE:
            return "Request entity too large";
        case HTTP_STATUS_REQUEST_URI_TOO_LARGE:
            return "Request URI too large";
        case HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
            return "Unsupported media type";
        case HTTP_STATUS_REQUEST_RANGE_INVALID:
            return "Request range invalid";
        case HTTP_STATUS_EXPECTATION_FAILED:
            return "Expectation failed";
        case HTTP_STATUS_INTERNAL_ERROR:
            return "Internal error";
        case HTTP_STATUS_NOT_IMPLEMENTED:
            return "Not implemented";
        case HTTP_STATUS_BAD_GATEWAY:
            return "Bad gateway";
        case HTTP_STATUS_SERVICE_UNAVAILABLE:
            return "Service unavailable";
        case HTTP_STATUS_GATEWAY_TIMEOUT:
            return "Gateway timeout";
        case HTTP_STATUS_BAD_VERSION:
            return "Bad version";
        default:
            return "ND";
    }
}

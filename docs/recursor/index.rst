Introduction
============
The PowerDNS Recursor is a high-performance DNS recursor with built-in scripting capabilities.
It is known to power the resolving needs of over 150 million internet connections.

The documentation is only for the 4.1 series, users of older versions are urged to upgrade!

Notable features
----------------

- Can handle tens of thousands of concurrent questions. A quad Xeon 3GHz has been measured functioning very well at 400000 real life replayed packets per second.
- Relies heavily on Standard C++ Library infrastructure, which makes for little code.
- Powered by a highly modern DNS packet parser that should be resistant against many forms of buffer overflows.
- Best spoofing protection that we know about, involving both source port randomisation and spoofing detection.
- Uses 'connected' UDP sockets which allow the recursor to react quickly to unreachable hosts or hosts for which the server is running, but the nameserver is down. This makes the recursor faster to respond in case of misconfigured domains, which are sadly very frequent.
- Special support for FreeBSD, Linux and Solaris stateful multiplexing (kqueue, epoll, completion ports, /dev/poll).
- Very fast, and contains innovative query-throttling code to save time talking to obsolete or broken nameservers.
- Code is written linearly, sequentially, which means that there are no problems with 'query restart' or anything.
- The algorithm is simple and quite nifty.
- Does DNSSEC validation
- Is highly scriptable in `Lua <http://lualang.org>`_

.. toctree::
    :hidden:
    :maxdepth: 2
    :glob:

    getting-started
    dnssec
    lua-config/index
    lua-scripting/index
    dns64
    settings
    manpages/*
    appendices/*


                          Basic Proxy

  What is it?
  -----------

  The basic proxy allows a client to setup a proxy that blocks certain
  websites stored in a txt file.

  Documentation
  -------------

  Included in the doc directory.

  Installation
  ------------

  Executing make in the main directory compiles all the files
  needed. The servers should be executed within each bin location.

  Files
  --------
  /bin/
      proxy: executable for the proxy program


  /doc/
      protocol.txt : A specification of the application-layer protocol.
      usage.txt : Documentation of the design usage.

  /src/
      proxy.c : contains the code for the implementation of the
      server. Imports functions from the following libraries: sys/types.h,
      sys/socket.h, strings.h, string.h, arpa/inet.h, stdio.h, stdlib.h,
      unistd.h and netinet/in.h
      Makefile : compiles proxy. Also contains a clean function


  Makefile : calls the Makefile in /src/ and also includes a clean
  function
  bannedWebs.txt: contains a list of the banned websites
  access.log: contains the log of the proxy

  Contacts
  --------

  Luis Serra Garcia, Creator: lserraga@ucsc.edu

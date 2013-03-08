Serval
======

For more and up-to-date information, see:

https://github.com/princeton-sns/serval/wiki

and 

http://www.serval-arch.org

Compilation
-----------

The first time you check out the source code, prepare the build
system:

```
./autogen.sh
```

To configure the build system (with common options):

```
./configure [ --enable-debug | --disable-kernel | --disable-service-router ]\
```

To build:

```
make
```

Directory structure
-------------------
**include/**			
>headers that are shared between components under src/.

**src/**			
>source code.

**src/common/** 		
>library with 'common' functionality.

**src/stack/**		
>stack code.

**src/stack/linux/**		
>stack code specific for the linux kernel.

**src/stack/userlevel/**	
>stack code specific for user level.

**src/servd/**		
>user space control daemon for the stack that takes local service
>registrations and passes them to a controller in the network. 

**src/test/**	
>test programs for the stack.

**src/translator**
>daemon that translates between PF\_INET and PF\_SERVAL TCP socket.

**src/tools**
>tools for controlling the Serval stack.

**src/libservalctrl/**
>library for communicating with and controlling Serval stacks, 
>either locally or remotely.

**src/libserval/**
>socket API abstraction for client applications interacting 
>with the user-level version of the stack.

**src/javasock/**
>Java bindings that make it possible to write Serval 
>applications in Java.

**android/**
>Android-specific files and applications.
	
Cross-compile Linux kernel module
---------------------------------

Prerequisites:

* Kernel source code matching your cross-compile environment.
* A tool-chain for your cross-compile architecture.

Run (```./autogen.sh```) ```./configure``` to generate Makefiles

Enter src/stack and issue the following command (example for Android):

```
make serval.ko ARCH=arm CROSS_COMPILE=<Path to NDK)/build/prebuilt/darwin-x86/arm-eabi-4.4.0/bin/arm-eabi- KDIR=<Path to kernel source>
```


Running Serval in kernel mode
-----------------------------

Insert the Serval kernel module:

```
insmod ./src/stack/serval.ko
```

Start servd (optional):

```
./src/servd/servd
```

Wait until a service router is discovered or a timeout occurs (in
which case host control mode is set).

Start an application, e.g.,:

```
./src/test/tcp_server
```

Access internal state and debug output through /proc/net/serval/ and
configuration parameters through /proc/sys/net/serval/.

When done, shut down all clients and servd, then remove Serval module:

```
rmmod serval
```

Running Serval in user-level mode
---------------------------------

Start the user-level stack

```
./src/stack/serval [ -i <iface> ]
```

Start servd (optional):

```
./src/servd/servd
```

Wait until a service router is discovered or a timeout occurs (in
which case host control mode is set).

Start an application, e.g.:

```
./src/test/tcp_server_user
```

Connect with telnet to 127.0.0.1:9999 for printing internal state.


Configuration Options
---------------------

```
/proc/sys/net/serval/auto_migrate             - Enable/Disable automigration between interfaces
/proc/sys/net/serval/debug                    - Set debug level
/proc/sys/net/serval/inet_to_serval           - Enable/Disable socket hijacking, where legacy (AF_INET) sockets are turned into Serval sockets
/proc/sys/net/serval/sal_forward              - Enable/Disable forwarding in SAL
/proc/sys/net/serval/sal_max_retransmits      - Max SAL retransmits
/proc/sys/net/serval/service_resolution_mode  - Specifies which rules to use when resolving services. 0=All, 1=Demux only, 2=forward only, 3=Anycast 
/proc/sys/net/serval/udp_encap                - Enable/Disable UDP encapsulation
/proc/sys/net/serval/udp_encap_client_port    - List/set client UDP encap port
/proc/sys/net/serval/udp_encap_server_port    - List/set server UDP encap port
```
